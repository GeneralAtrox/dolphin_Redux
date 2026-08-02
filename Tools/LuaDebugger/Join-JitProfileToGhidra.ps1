# SPDX-License-Identifier: GPL-2.0-or-later
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ProfilePath,
  [Parameter(Mandatory)][string]$GhidraCatalogPath,
  [string[]]$AdditionalCatalogPath = @(),
  [switch]$AllowAddressOnly,
  [switch]$AllowUnresolvedCatalog,
  [Parameter(Mandatory)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

function Identity([string]$Path) {
  $resolved = [IO.Path]::GetFullPath($Path)
  $item = Get-Item -LiteralPath $resolved -ErrorAction Stop
  [ordered]@{
    path = $resolved
    length = $item.Length
    sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}

function Convert-HexToBytes([string]$Hex, [string]$Label) {
  if (($Hex.Length % 2) -ne 0 -or $Hex -notmatch '\A[0-9a-fA-F]*\z') {
    throw "$Label is not an even-length hexadecimal byte string."
  }
  $bytes = [byte[]]::new($Hex.Length / 2)
  for ($index = 0; $index -lt $bytes.Length; ++$index) {
    $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
  }
  return $bytes
}

function Get-Sha256Hex([byte[]]$Bytes) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

$resolvedProfile = [IO.Path]::GetFullPath($ProfilePath)
$resolvedCatalog = [IO.Path]::GetFullPath($GhidraCatalogPath)
$resolvedAdditionalCatalogs = @($AdditionalCatalogPath | ForEach-Object { [IO.Path]::GetFullPath($_) })
$resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
$profileDocument = Get-Content -LiteralPath $resolvedProfile -Raw | ConvertFrom-Json -Depth 100
$profile = if ($profileDocument.PSObject.Properties.Name -contains 'jit_profile') {
  $profileDocument.jit_profile
} else {
  $profileDocument
}
$profileHasCodeIdentity = $profile.schema -ceq 'dolphin-redux.jit-profile.v2'
if (($profile.schema -cne 'dolphin-redux.jit-profile.v1' -and -not $profileHasCodeIdentity) -or
    $profile.ok -ne $true) {
  throw 'Input does not contain a successful dolphin-redux.jit-profile.v1 or v2 snapshot.'
}
if (-not $profileHasCodeIdentity -and -not $AllowAddressOnly) {
  throw 'JIT profile has no code identity. Use a v2 capture or explicitly pass -AllowAddressOnly.'
}
if ($profileHasCodeIdentity -and
    ($profile.code_identity_complete -ne $true -or
     [uint64]$profile.code_identity_blocks -ne [uint64]$profile.executed_blocks)) {
  throw 'JIT profile does not contain code identity for every executed block.'
}
if ($profile.profiling_enabled -ne $true -or [uint64]$profile.executed_blocks -eq 0) {
  throw 'JIT snapshot is disabled or contains no executed blocks.'
}
if ([uint64]$profile.unprofiled_blocks -ne 0) {
  throw 'JIT snapshot contains blocks compiled without profiling; scene coverage is incomplete.'
}

$catalogPaths = @($resolvedCatalog) + $resolvedAdditionalCatalogs
$catalogFunctions = @(
  Get-Content -LiteralPath $catalogPaths |
      Where-Object { $_ } | ForEach-Object {
    $function = $_ | ConvertFrom-Json
    $start = [Convert]::ToUInt32([string]$function.address, 16)
    $hasExactBodyRanges = $function.PSObject.Properties.Name -contains 'body_ranges'
    [pscustomobject]@{
      start = $start
      address = ([string]$function.address).ToLowerInvariant()
      name = [string]$function.ghidra_name
      size = [uint64]$function.size
      exact_body_ranges = $hasExactBodyRanges
      body_ranges = if ($hasExactBodyRanges) {
        @($function.body_ranges)
      } else {
        @([pscustomobject]@{ start = ([string]$function.address); end = ('{0:x8}' -f ([uint64]$start + [uint64]$function.size - 1)) })
      }
    }
  }
)
if ($catalogFunctions.Count -eq 0) { throw 'Ghidra catalog contains no functions.' }

$functionRanges = @(@(
  foreach ($function in $catalogFunctions) {
    foreach ($range in @($function.body_ranges)) {
      $rangeStart = [Convert]::ToUInt32([string]$range.start, 16)
      $rangeEnd = [Convert]::ToUInt32([string]$range.end, 16)
      if ($rangeEnd -lt $rangeStart) { throw "Ghidra catalog contains a reversed function range for $($function.address)." }
      [pscustomobject]@{
        start = $rangeStart
        end = [uint64]$rangeEnd
        function_start = $function.start
        address = $function.address
        name = $function.name
        size = $function.size
        exact_body_range = $function.exact_body_ranges
        bytes_hex = if ($range.PSObject.Properties.Name -contains 'bytes') {
          ([string]$range.bytes).ToLowerInvariant()
        } else { $null }
        bytes_sha256 = if ($range.PSObject.Properties.Name -contains 'sha256') {
          ([string]$range.sha256).ToLowerInvariant()
        } else { $null }
        hash_verified = $false
      }
    }
  }
) | Sort-Object start, end)
for ($index = 1; $index -lt $functionRanges.Count; ++$index) {
  if ($functionRanges[$index].exact_body_range -and
      $functionRanges[$index - 1].exact_body_range -and
      [uint64]$functionRanges[$index].start -le [uint64]$functionRanges[$index - 1].end) {
    throw "Ghidra catalog contains overlapping function body ranges at $($functionRanges[$index].address)."
  }
}

function Resolve-Function([uint32]$Address) {
  $low = 0
  $high = $functionRanges.Count - 1
  $candidate = $null
  while ($low -le $high) {
    $middle = [int](($low + $high) / 2)
    if ($functionRanges[$middle].start -le $Address) {
      $candidate = $functionRanges[$middle]
      $low = $middle + 1
    } else {
      $high = $middle - 1
    }
  }
  if ($candidate -and [uint64]$Address -le $candidate.end) { return $candidate }
  return $null
}

function Assert-RangeIdentity($Range) {
  if ($Range.hash_verified) { return }
  if ([string]::IsNullOrEmpty($Range.bytes_hex) -or
      [string]::IsNullOrEmpty($Range.bytes_sha256)) {
    throw "Catalog range $($Range.address) [$('{0:x8}' -f $Range.start), $('{0:x8}' -f $Range.end)] has no byte identity."
  }
  $expectedLength = ([uint64]$Range.end - [uint64]$Range.start + 1) * 2
  if ([uint64]$Range.bytes_hex.Length -ne $expectedLength) {
    throw "Catalog range $($Range.address) byte length does not match its address range."
  }
  $bytes = Convert-HexToBytes $Range.bytes_hex "Catalog range $($Range.address) bytes"
  if ((Get-Sha256Hex $bytes) -cne $Range.bytes_sha256) {
    throw "Catalog range $($Range.address) SHA-256 does not match its bytes."
  }
  $Range.hash_verified = $true
}

function Test-BlockIdentity($Block, $Function, [bool]$AllowMissingCatalog) {
  if ($Block.code_identity_available -ne $true) {
    throw "JIT block $($Block.ppc_address) has no code identity."
  }
  $codeHex = ([string]$Block.code_bytes).ToLowerInvariant()
  $codeBytes = Convert-HexToBytes $codeHex "JIT block $($Block.ppc_address) code_bytes"
  if ($codeBytes.Length -ne [uint32]$Block.ppc_size) {
    throw "JIT block $($Block.ppc_address) code byte count does not match ppc_size."
  }
  if ((Get-Sha256Hex $codeBytes) -cne ([string]$Block.code_sha256).ToLowerInvariant()) {
    throw "JIT block $($Block.ppc_address) SHA-256 does not match its bytes."
  }
  $addresses = @($Block.instruction_addresses)
  if ($addresses.Count * 4 -ne $codeBytes.Length) {
    throw "JIT block $($Block.ppc_address) instruction address count does not match its bytes."
  }
  $spannedFunctions = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $missingAddresses = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  for ($index = 0; $index -lt $addresses.Count; ++$index) {
    $instructionAddress = [Convert]::ToUInt32([string]$addresses[$index], 16)
    $instructionRange = Resolve-Function $instructionAddress
    if (-not $instructionRange) {
      if (-not $AllowMissingCatalog) {
        throw "JIT block $($Block.ppc_address) instruction $($addresses[$index]) is outside every catalog function."
      }
      [void]$missingAddresses.Add(('{0:x8}' -f $instructionAddress))
      continue
    }
    if ($index -eq 0 -and $Function -and $instructionRange.address -cne $Function.address) {
      throw "JIT block $($Block.ppc_address) entry instruction does not belong to resolved function $($Function.address)."
    }
    [void]$spannedFunctions.Add($instructionRange.address)
    Assert-RangeIdentity $instructionRange
    $rangeByteOffset = ([uint64]$instructionAddress - [uint64]$instructionRange.start) * 2
    if ($rangeByteOffset + 8 -gt $instructionRange.bytes_hex.Length) {
      throw "Catalog range $($instructionRange.address) does not contain a complete instruction at $($addresses[$index])."
    }
    $expectedWord = $instructionRange.bytes_hex.Substring([int]$rangeByteOffset, 8)
    $actualWord = $codeHex.Substring($index * 8, 8)
    if ($actualWord -cne $expectedWord) {
      throw "JIT block $($Block.ppc_address) instruction bytes differ from catalog at $($addresses[$index])."
    }
  }
  return [pscustomobject]@{
    function_addresses = @($spannedFunctions | Sort-Object)
    missing_addresses = @($missingAddresses | Sort-Object)
  }
}

$joinedBlocks = @(
  foreach ($block in @($profile.blocks)) {
    if ([uint64]$block.run_count -eq 0) { continue }
    $address = [Convert]::ToUInt32([string]$block.ppc_address, 16)
    $function = Resolve-Function $address
    $identityVerified = $false
    $identityFunctionAddresses = @()
    $missingCatalogInstructionAddresses = @()
    if ($profileHasCodeIdentity -and ($function -or $AllowUnresolvedCatalog)) {
      $identity = Test-BlockIdentity $block $function ([bool]$AllowUnresolvedCatalog)
      $identityFunctionAddresses = @($identity.function_addresses)
      $missingCatalogInstructionAddresses = @($identity.missing_addresses)
      $identityVerified = $null -ne $function -and $missingCatalogInstructionAddresses.Count -eq 0
    }
    [pscustomobject][ordered]@{
      ppc_address = ([string]$block.ppc_address).ToLowerInvariant()
      physical_address = ([string]$block.physical_address).ToLowerInvariant()
      ppc_size = [uint32]$block.ppc_size
      feature_flags = [uint32]$block.feature_flags
      run_count = [uint64]$block.run_count
      cycles_spent = [uint64]$block.cycles_spent
      dolphin_symbol = [string]$block.symbol
      resolved = $null -ne $function
      identity_verified = $identityVerified
      identity_function_addresses = $identityFunctionAddresses
      catalog_coverage_complete = $profileHasCodeIdentity -and
          $missingCatalogInstructionAddresses.Count -eq 0
      missing_catalog_instruction_addresses = $missingCatalogInstructionAddresses
      ghidra_function_address = if ($function) { $function.address } else { $null }
      ghidra_function_name = if ($function) { $function.name } else { $null }
      function_offset = if ($function) { [uint32]($address - $function.function_start) } else { $null }
    }
  }
)

$functionRows = @(
  $joinedBlocks | Where-Object resolved | Group-Object ghidra_function_address | ForEach-Object {
    $rows = @($_.Group)
    [pscustomobject][ordered]@{
      ghidra_function_address = $rows[0].ghidra_function_address
      ghidra_function_name = $rows[0].ghidra_function_name
      executed_block_count = $rows.Count
      run_count = [uint64](($rows | Measure-Object run_count -Sum).Sum)
      cycles_spent = [uint64](($rows | Measure-Object cycles_spent -Sum).Sum)
    }
  } | Sort-Object @{Expression = 'cycles_spent'; Descending = $true}, ghidra_function_address
)
$unresolved = @($joinedBlocks | Where-Object { -not $_.resolved })
$identityVerified = @($joinedBlocks | Where-Object identity_verified)
[object[]]$addressOnly = @()
if (-not $profileHasCodeIdentity) {
  $addressOnly = @($joinedBlocks | Where-Object { $_.resolved -and -not $_.identity_verified })
}
[object[]]$catalogIncomplete = @()
if ($profileHasCodeIdentity) {
  $catalogIncomplete = @($joinedBlocks | Where-Object { -not $_.catalog_coverage_complete })
}
$result = [ordered]@{
  schema = 'dolphin-redux.ghidra-scene-join.v2'
  profile = Identity $resolvedProfile
  ghidra_catalog = Identity $resolvedCatalog
  additional_catalogs = @($resolvedAdditionalCatalogs | ForEach-Object { Identity $_ })
  counts = [ordered]@{
    catalog_functions = $catalogFunctions.Count
    executed_blocks = $joinedBlocks.Count
    resolved_blocks = $joinedBlocks.Count - $unresolved.Count
    unresolved_blocks = $unresolved.Count
    identity_verified_blocks = $identityVerified.Count
    address_only_blocks = $addressOnly.Count
    catalog_incomplete_blocks = $catalogIncomplete.Count
    executed_functions = $functionRows.Count
  }
  functions = $functionRows
  blocks = $joinedBlocks
  unresolved_blocks = $unresolved
  address_only_blocks = $addressOnly
  catalog_incomplete_blocks = $catalogIncomplete
}
$directory = [IO.Path]::GetDirectoryName($resolvedOutput)
if ($directory) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
$result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resolvedOutput -Encoding utf8
$result
