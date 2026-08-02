# SPDX-License-Identifier: GPL-2.0-or-later
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ProfilePath,
  [Parameter(Mandatory)][string]$GhidraCatalogPath,
  [string[]]$AdditionalCatalogPath = @(),
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
$document = Get-Content -LiteralPath $resolvedProfile -Raw | ConvertFrom-Json -Depth 100
$profile = if ($document.PSObject.Properties.Name -contains 'branch_profile') {
  $document.branch_profile
} else {
  $document
}
if ($profile.schema -cne 'dolphin-redux.branch-profile.v1' -or $profile.ok -ne $true) {
  throw 'Input does not contain a successful dolphin-redux.branch-profile.v1 snapshot.'
}
if ($profile.recording_active -ne $true) {
  throw 'Branch profile snapshot was not recorded from an active branch watch.'
}
if ([uint64]$profile.distinct_edges -ne @($profile.edges).Count) {
  throw 'Branch profile distinct-edge count differs from its edge array.'
}

$catalogFunctions = @(
  Get-Content -LiteralPath (@($resolvedCatalog) + $resolvedAdditionalCatalogs) |
      Where-Object { $_ } | ForEach-Object {
    $function = $_ | ConvertFrom-Json
    [pscustomobject]@{
      start = [Convert]::ToUInt32([string]$function.address, 16)
      address = ([string]$function.address).ToLowerInvariant()
      name = [string]$function.ghidra_name
      body_ranges = @($function.body_ranges)
    }
  }
)
if ($catalogFunctions.Count -eq 0) { throw 'Ghidra catalog contains no functions.' }

$functionRanges = @(@(
  foreach ($function in $catalogFunctions) {
    foreach ($range in $function.body_ranges) {
      $rangeStart = [Convert]::ToUInt32([string]$range.start, 16)
      $rangeEnd = [Convert]::ToUInt32([string]$range.end, 16)
      if ($rangeEnd -lt $rangeStart) {
        throw "Ghidra catalog contains a reversed function range for $($function.address)."
      }
      if (-not ($range.PSObject.Properties.Name -contains 'bytes') -or
          -not ($range.PSObject.Properties.Name -contains 'sha256')) {
        throw "Catalog range $($function.address) has no byte identity."
      }
      [pscustomobject]@{
        start = $rangeStart
        end = [uint64]$rangeEnd
        function_start = $function.start
        address = $function.address
        name = $function.name
        bytes_hex = ([string]$range.bytes).ToLowerInvariant()
        bytes_sha256 = ([string]$range.sha256).ToLowerInvariant()
        hash_verified = $false
      }
    }
  }
) | Sort-Object start, end)
for ($index = 1; $index -lt $functionRanges.Count; ++$index) {
  if ([uint64]$functionRanges[$index].start -le [uint64]$functionRanges[$index - 1].end) {
    throw "Ghidra catalog contains overlapping function ranges at $($functionRanges[$index].address)."
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
  $expectedHexLength = ([uint64]$Range.end - [uint64]$Range.start + 1) * 2
  if ([uint64]$Range.bytes_hex.Length -ne $expectedHexLength) {
    throw "Catalog range $($Range.address) byte length does not match its addresses."
  }
  $bytes = Convert-HexToBytes $Range.bytes_hex "Catalog range $($Range.address) bytes"
  if ((Get-Sha256Hex $bytes) -cne $Range.bytes_sha256) {
    throw "Catalog range $($Range.address) SHA-256 does not match its bytes."
  }
  $Range.hash_verified = $true
}

function Get-BranchClassification([uint32]$Instruction) {
  $opcode = $Instruction -shr 26
  $link = ($Instruction -band 1) -ne 0
  if ($opcode -eq 18) {
    return [pscustomobject]@{ kind = if ($link) { 'bl' } else { 'b' }; link = $link; indirect = $false; lr_transfer = $false }
  }
  if ($opcode -eq 16) {
    return [pscustomobject]@{ kind = if ($link) { 'bcl' } else { 'bc' }; link = $link; indirect = $false; lr_transfer = $false }
  }
  if ($opcode -eq 19) {
    $subop = ($Instruction -shr 1) -band 0x3ff
    if ($subop -eq 16) {
      return [pscustomobject]@{ kind = if ($link) { 'bclrl' } else { 'bclr' }; link = $link; indirect = $true; lr_transfer = $true }
    }
    if ($subop -eq 528) {
      return [pscustomobject]@{ kind = if ($link) { 'bcctrl' } else { 'bcctr' }; link = $link; indirect = $true; lr_transfer = $false }
    }
  }
  throw ('Branch profile contains non-branch instruction {0:x8}.' -f $Instruction)
}

$joinedEdges = @(
  foreach ($edge in @($profile.edges)) {
    if ([uint64]$edge.hits -eq 0) { throw 'Branch profile contains a zero-hit edge.' }
    if ([string]$edge.address_space -cne 'virtual' -and
        [string]$edge.address_space -cne 'physical') {
      throw "Branch profile contains invalid address space '$($edge.address_space)'."
    }
    $origin = [Convert]::ToUInt32([string]$edge.origin, 16)
    $destination = [Convert]::ToUInt32([string]$edge.destination, 16)
    $instruction = [Convert]::ToUInt32([string]$edge.instruction, 16)
    $source = Resolve-Function $origin
    if (-not $source) {
      throw "Branch source $($edge.origin) is outside every catalog function."
    }
    Assert-RangeIdentity $source
    $byteOffset = ([uint64]$origin - [uint64]$source.start) * 2
    if ($byteOffset + 8 -gt $source.bytes_hex.Length) {
      throw "Catalog range $($source.address) has no complete instruction at $($edge.origin)."
    }
    $expectedInstruction = $source.bytes_hex.Substring([int]$byteOffset, 8)
    if ($expectedInstruction -cne ('{0:x8}' -f $instruction)) {
      throw "Branch instruction differs from the catalog at $($edge.origin)."
    }
    $target = Resolve-Function $destination
    if (-not $target) {
      throw "Branch destination $($edge.destination) is outside every catalog function."
    }
    Assert-RangeIdentity $target
    $classification = Get-BranchClassification $instruction
    $taken = $edge.taken -eq $true
    [pscustomobject][ordered]@{
      origin = ('{0:x8}' -f $origin)
      destination = ('{0:x8}' -f $destination)
      instruction = ('{0:x8}' -f $instruction)
      hits = [uint64]$edge.hits
      taken = $taken
      address_space = [string]$edge.address_space
      branch_kind = $classification.kind
      indirect = [bool]$classification.indirect
      is_call = $taken -and [bool]$classification.link
      is_lr_transfer = $taken -and [bool]$classification.lr_transfer
      enters_function = $taken -and $destination -eq $target.function_start
      instruction_identity_verified = $true
      source_function_address = $source.address
      source_function_name = $source.name
      destination_function_address = $target.address
      destination_function_name = $target.name
    }
  }
)

$callEdges = @($joinedEdges | Where-Object is_call)
$entryEdges = @($joinedEdges | Where-Object enters_function)
$lrTransferEdges = @($joinedEdges | Where-Object is_lr_transfer)
$joinedTotalHits = [uint64](($joinedEdges | Measure-Object hits -Sum).Sum)
if ($joinedTotalHits -ne [uint64]$profile.total_hits -or
    @($joinedEdges | Where-Object taken).Count -ne [uint64]$profile.taken_edges -or
    @($joinedEdges | Where-Object { -not $_.taken }).Count -ne [uint64]$profile.not_taken_edges) {
  throw 'Branch profile summary counts differ from the joined edge records.'
}
$enteredFunctions = @(
  $entryEdges | Group-Object destination_function_address | ForEach-Object {
    $rows = @($_.Group)
    [pscustomobject][ordered]@{
      function_address = $rows[0].destination_function_address
      function_name = $rows[0].destination_function_name
      incoming_edge_count = $rows.Count
      hits = [uint64](($rows | Measure-Object hits -Sum).Sum)
    }
  } | Sort-Object function_address
)
$boundary = $null
if ($document.PSObject.Properties.Name -contains 'branch_profile_reset' -and
    $document.branch_profile_reset -and $document.branch_profile_reset.pc) {
  $boundaryPc = [Convert]::ToUInt32([string]$document.branch_profile_reset.pc, 16)
  $boundaryFunction = Resolve-Function $boundaryPc
  if (-not $boundaryFunction) {
    throw "Branch reset boundary PC $($document.branch_profile_reset.pc) is outside every catalog function."
  }
  $boundary = [ordered]@{
    pc = ('{0:x8}' -f $boundaryPc)
    function_address = $boundaryFunction.address
    function_name = $boundaryFunction.name
  }
}

$result = [ordered]@{
  schema = 'dolphin-redux.ghidra-branch-join.v1'
  profile = Identity $resolvedProfile
  ghidra_catalog = Identity $resolvedCatalog
  additional_catalogs = @($resolvedAdditionalCatalogs | ForEach-Object { Identity $_ })
  reset_boundary = $boundary
  counts = [ordered]@{
    catalog_functions = $catalogFunctions.Count
    distinct_edges = $joinedEdges.Count
    identity_verified_edges = @($joinedEdges | Where-Object instruction_identity_verified).Count
    taken_edges = @($joinedEdges | Where-Object taken).Count
    not_taken_edges = @($joinedEdges | Where-Object { -not $_.taken }).Count
    call_edges = $callEdges.Count
    lr_transfer_edges = $lrTransferEdges.Count
    function_entry_edges = $entryEdges.Count
    entered_functions = $enteredFunctions.Count
  }
  entered_functions = $enteredFunctions
  call_edges = $callEdges
  function_entry_edges = $entryEdges
  lr_transfer_edges = $lrTransferEdges
  edges = $joinedEdges
}
$directory = [IO.Path]::GetDirectoryName($resolvedOutput)
if ($directory) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
$result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resolvedOutput -Encoding utf8
$result
