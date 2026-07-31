# SPDX-License-Identifier: GPL-2.0-or-later
[CmdletBinding(PositionalBinding = $false)]
param(
  [string]$PipeName = $env:SOAL_PIPE_NAME,
  [ValidateRange(10, 60000)][int]$ConnectTimeoutMilliseconds = 5000,
  [ValidateRange(10, 60000)][int]$ResponseTimeoutMilliseconds = 5000,
  [ValidateRange(1024, 134217728)][int]$MaximumResponseBytes = 262144,
  [ValidateRange(1000, 5000000)][int]$MaximumJsonNodes = 50000,
  [ValidateRange(10, 60000)][int]$WatchIntervalMilliseconds = 100,
  [ValidateRange(0, 2147483647)][int]$WatchPollCount = 0,
  [ValidateRange(0, 2147483647)][int]$ExpectedServerProcessId = 0,
  [ValidateRange(0, 3155378975999999999)][long]$ExpectedServerStartTimeUtcTicks = 0,
  [string]$ExpectedServerImagePath,
  [string]$ExpectedServerUserSid,
  [Parameter(Position = 0, ValueFromRemainingArguments = $true)][string[]]$Command
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

if (-not ('SoALCli.AuthenticatedPipe' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SoALCli
{
  public sealed class NativeOrdinalIgnoreCaseComparer : IComparer<string>
  {
    public static readonly NativeOrdinalIgnoreCaseComparer Instance =
        new NativeOrdinalIgnoreCaseComparer();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int CompareStringOrdinal(
        string left, int leftLength, string right, int rightLength, bool ignoreCase);
    private NativeOrdinalIgnoreCaseComparer() { }
    public int Compare(string left, string right)
    {
      if (object.ReferenceEquals(left, right)) return 0;
      if (left == null) return -1;
      if (right == null) return 1;
      int result = CompareStringOrdinal(left, left.Length, right, right.Length, true);
      if (result == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
      return result - 2;
    }
    public static bool EqualsOrdinalIgnoreCase(string left, string right)
    { return Instance.Compare(left, right) == 0; }
  }

  public static class AuthenticatedPipe
  {
    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
      public uint Low;
      public uint High;
      public long ToInt64() { return unchecked((long)(((ulong)High << 32) | Low)); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
      public IntPtr Sid;
      public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenUser
    {
      public SidAndAttributes User;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr process, uint flags, StringBuilder imagePath, ref uint imagePathLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(
        IntPtr process, out FileTime creation, out FileTime exit,
        out FileTime kernel, out FileTime user);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr token, int informationClass, IntPtr information,
        uint informationLength, out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static string ProcessUserSid(IntPtr process)
    {
      IntPtr token;
      if (!OpenProcessToken(process, 0x0008u, out token))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      try
      {
        uint length;
        GetTokenInformation(token, 1, IntPtr.Zero, 0, out length);
        int expectedError = Marshal.GetLastWin32Error();
        if (length == 0 || expectedError != 122)
          throw new Win32Exception(expectedError);
        IntPtr buffer = Marshal.AllocHGlobal(checked((int)length));
        try
        {
          if (!GetTokenInformation(token, 1, buffer, length, out length))
            throw new Win32Exception(Marshal.GetLastWin32Error());
          TokenUser user = (TokenUser)Marshal.PtrToStructure(buffer, typeof(TokenUser));
          return new SecurityIdentifier(user.User.Sid).Value;
        }
        finally
        {
          Marshal.FreeHGlobal(buffer);
        }
      }
      finally
      {
        CloseHandle(token);
      }
    }

    public static void Verify(SafePipeHandle pipe, uint expectedProcessId,
                              long expectedStartTimeUtcTicks, string expectedImagePath,
                              string expectedUserSid)
    {
      uint serverProcessId;
      if (!GetNamedPipeServerProcessId(pipe, out serverProcessId))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      if (serverProcessId != expectedProcessId)
        throw new InvalidOperationException(
            "named-pipe server PID " + serverProcessId +
            " does not match owned Dolphin PID " + expectedProcessId);

      IntPtr process = OpenProcess(0x00001000u, false, serverProcessId);
      if (process == IntPtr.Zero)
        throw new Win32Exception(Marshal.GetLastWin32Error());
      try
      {
        FileTime creation, exit, kernel, user;
        if (!GetProcessTimes(process, out creation, out exit, out kernel, out user))
          throw new Win32Exception(Marshal.GetLastWin32Error());
        long actualStartTimeUtcTicks = DateTime.FromFileTimeUtc(creation.ToInt64()).Ticks;
        if (actualStartTimeUtcTicks != expectedStartTimeUtcTicks)
          throw new InvalidOperationException("named-pipe server process creation time changed");

        StringBuilder image = new StringBuilder(32768);
        uint imageLength = (uint)image.Capacity;
        if (!QueryFullProcessImageNameW(process, 0, image, ref imageLength))
          throw new Win32Exception(Marshal.GetLastWin32Error());
        if (!NativeOrdinalIgnoreCaseComparer.EqualsOrdinalIgnoreCase(
                image.ToString(), expectedImagePath))
          throw new InvalidOperationException("named-pipe server image path changed");

        string actualUserSid = ProcessUserSid(process);
        if (!NativeOrdinalIgnoreCaseComparer.EqualsOrdinalIgnoreCase(
                actualUserSid, expectedUserSid))
          throw new InvalidOperationException("named-pipe server token SID changed");
      }
      finally
      {
        CloseHandle(process);
      }
    }
  }

  public static class StrictJsonGuard
  {
    public static void Validate(string text, int maximumCharacters, int maximumDepth,
                                int maximumNodes)
    {
      if (text == null || text.Length == 0 || text.Length > maximumCharacters)
        throw new FormatException("JSON length is outside the accepted bound.");
      Parser parser = new Parser(text, maximumDepth, maximumNodes);
      parser.ParseDocument();
    }

    private sealed class Parser
    {
      private readonly string m_text;
      private readonly int m_maximumDepth;
      private readonly int m_maximumNodes;
      private int m_offset;
      private int m_nodes;

      public Parser(string text, int maximumDepth, int maximumNodes)
      {
        m_text = text;
        m_maximumDepth = maximumDepth;
        m_maximumNodes = maximumNodes;
      }

      public void ParseDocument()
      {
        ParseValue(0);
        if (m_offset != m_text.Length)
          Fail("Trailing data");
      }

      private void ParseValue(int depth)
      {
        if (depth > m_maximumDepth)
          Fail("JSON nesting exceeds its bound");
        if (++m_nodes > m_maximumNodes)
          Fail("JSON node count exceeds its bound");
        if (m_offset >= m_text.Length)
          Fail("Unexpected end of JSON");
        char current = m_text[m_offset];
        if (current == '{') ParseObject(depth + 1);
        else if (current == '[') ParseArray(depth + 1);
        else if (current == '"') ParseString();
        else if (current == 't') ParseLiteral("true");
        else if (current == 'f') ParseLiteral("false");
        else if (current == 'n') ParseLiteral("null");
        else if (current == '-' || (current >= '0' && current <= '9')) ParseNumber();
        else Fail("Unexpected JSON token");
      }

      private void ParseObject(int depth)
      {
        ++m_offset;
        SortedSet<string> names = new SortedSet<string>(NativeOrdinalIgnoreCaseComparer.Instance);
        if (Take('}')) return;
        while (true)
        {
          if (m_offset >= m_text.Length || m_text[m_offset] != '"')
            Fail("Object member name is not a JSON string");
          string name = ParseString();
          if (!names.Add(name)) Fail("Duplicate or case-colliding object member");
          Require(':');
          ParseValue(depth);
          if (Take('}')) return;
          Require(',');
        }
      }

      private void ParseArray(int depth)
      {
        ++m_offset;
        if (Take(']')) return;
        while (true)
        {
          ParseValue(depth);
          if (Take(']')) return;
          Require(',');
        }
      }

      private string ParseString()
      {
        Require('"');
        StringBuilder value = new StringBuilder();
        while (m_offset < m_text.Length)
        {
          char current = m_text[m_offset++];
          if (current == '"') return value.ToString();
          if (current < 0x20) Fail("Unescaped control character in JSON string");
          if (current != '\\')
          {
            if (char.IsHighSurrogate(current))
            {
              if (m_offset >= m_text.Length || !char.IsLowSurrogate(m_text[m_offset]))
                Fail("Unpaired high surrogate in JSON string");
              value.Append(current);
              value.Append(m_text[m_offset++]);
              continue;
            }
            if (char.IsLowSurrogate(current))
              Fail("Unpaired low surrogate in JSON string");
            value.Append(current);
            continue;
          }
          if (m_offset >= m_text.Length) Fail("Incomplete JSON escape");
          char escaped = m_text[m_offset++];
          switch (escaped)
          {
          case '"': value.Append('"'); break;
          case '\\': value.Append('\\'); break;
          case '/': value.Append('/'); break;
          case 'b': value.Append('\b'); break;
          case 'f': value.Append('\f'); break;
          case 'n': value.Append('\n'); break;
          case 'r': value.Append('\r'); break;
          case 't': value.Append('\t'); break;
          case 'u':
          {
            char unit = ParseUnicodeEscape();
            if (char.IsHighSurrogate(unit))
            {
              if (m_offset + 6 > m_text.Length || m_text[m_offset] != '\\' ||
                  m_text[m_offset + 1] != 'u')
                Fail("Escaped high surrogate is not followed by an escaped low surrogate");
              m_offset += 2;
              char low = ParseUnicodeEscape();
              if (!char.IsLowSurrogate(low))
                Fail("Escaped high surrogate is not followed by an escaped low surrogate");
              value.Append(unit);
              value.Append(low);
            }
            else
            {
              if (char.IsLowSurrogate(unit))
                Fail("Unpaired escaped low surrogate in JSON string");
              value.Append(unit);
            }
            break;
          }
          default: Fail("Invalid JSON escape"); break;
          }
        }
        Fail("Unterminated JSON string");
        return null;
      }

      private char ParseUnicodeEscape()
      {
        if (m_offset + 4 > m_text.Length) Fail("Incomplete JSON Unicode escape");
        int value = 0;
        for (int index = 0; index < 4; ++index)
        {
          char digit = m_text[m_offset++];
          int nibble = digit >= '0' && digit <= '9' ? digit - '0' :
                       digit >= 'a' && digit <= 'f' ? digit - 'a' + 10 :
                       digit >= 'A' && digit <= 'F' ? digit - 'A' + 10 : -1;
          if (nibble < 0) Fail("Invalid JSON Unicode escape");
          value = (value << 4) | nibble;
        }
        return (char)value;
      }

      private void ParseLiteral(string literal)
      {
        if (m_offset + literal.Length > m_text.Length ||
            string.CompareOrdinal(m_text, m_offset, literal, 0, literal.Length) != 0)
          Fail("Invalid JSON literal");
        m_offset += literal.Length;
      }

      private void ParseNumber()
      {
        if (Take('-') && m_offset >= m_text.Length) Fail("Incomplete JSON number");
        if (Take('0'))
        {
          if (m_offset < m_text.Length && IsAsciiDigit(m_text[m_offset]))
            Fail("JSON number has a leading zero");
        }
        else
        {
          if (m_offset >= m_text.Length || m_text[m_offset] < '1' || m_text[m_offset] > '9')
            Fail("Invalid JSON integer");
          while (m_offset < m_text.Length && IsAsciiDigit(m_text[m_offset])) ++m_offset;
        }
        if (Take('.'))
        {
          if (m_offset >= m_text.Length || !IsAsciiDigit(m_text[m_offset]))
            Fail("Invalid JSON fraction");
          while (m_offset < m_text.Length && IsAsciiDigit(m_text[m_offset])) ++m_offset;
        }
        if (m_offset < m_text.Length && (m_text[m_offset] == 'e' || m_text[m_offset] == 'E'))
        {
          ++m_offset;
          if (m_offset < m_text.Length && (m_text[m_offset] == '+' || m_text[m_offset] == '-'))
            ++m_offset;
          if (m_offset >= m_text.Length || !IsAsciiDigit(m_text[m_offset]))
            Fail("Invalid JSON exponent");
          while (m_offset < m_text.Length && IsAsciiDigit(m_text[m_offset])) ++m_offset;
        }
      }

      private static bool IsAsciiDigit(char value)
      { return value >= '0' && value <= '9'; }

      private bool Take(char expected)
      {
        if (m_offset < m_text.Length && m_text[m_offset] == expected)
        { ++m_offset; return true; }
        return false;
      }
      private void Require(char expected)
      { if (!Take(expected)) Fail("Expected JSON delimiter"); }
      private void Fail(string message)
      { throw new FormatException(message + " at offset " + m_offset + "."); }
    }
  }
}
'@
}

if (-not $Command -or $Command.Count -eq 0) {
  throw 'Usage: soal-cli.ps1 [-ExpectedServerProcessId PID -ExpectedServerStartTimeUtcTicks TICKS -ExpectedServerImagePath PATH -ExpectedServerUserSid SID] <command>'
}
if (-not $PipeName) { $PipeName = 'dolphin-redux' }
if ($PipeName -cnotmatch '^[A-Za-z0-9._-]{1,128}$') {
  throw 'PipeName is not a bounded canonical local named-pipe leaf.'
}

$identityValues = @($ExpectedServerStartTimeUtcTicks, $ExpectedServerImagePath,
                    $ExpectedServerUserSid)
if ($ExpectedServerProcessId -gt 0) {
  if ($ExpectedServerStartTimeUtcTicks -le 0 -or
      [string]::IsNullOrWhiteSpace($ExpectedServerImagePath) -or
      [string]::IsNullOrWhiteSpace($ExpectedServerUserSid)) {
    throw 'A trusted pipe connection requires PID, creation time, image path, and token SID.'
  }
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if ($currentSid -cne $ExpectedServerUserSid) {
    throw 'Expected pipe-server SID differs from the invoking principal SID.'
  }
}
elseif ($ExpectedServerStartTimeUtcTicks -ne 0 -or $ExpectedServerImagePath -or
        $ExpectedServerUserSid) {
  throw 'Partial pipe-server identity is forbidden.'
}

function Read-BoundedPipeResponse {
  param(
    [Parameter(Mandatory = $true)][System.IO.StreamReader]$Reader,
    [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds,
    [Parameter(Mandatory = $true)][int]$MaximumBytes
  )
  $timer = [Diagnostics.Stopwatch]::StartNew()
  $builder = [Text.StringBuilder]::new()
  $buffer = [char[]]::new(4096)
  while ($true) {
    $remaining = $TimeoutMilliseconds - [int]$timer.ElapsedMilliseconds
    if ($remaining -le 0) {
      throw "Timed out after $TimeoutMilliseconds ms waiting for a control-server reply."
    }
    $read = $Reader.ReadAsync($buffer, 0, $buffer.Length)
    if (-not $read.Wait($remaining)) {
      throw "Timed out after $TimeoutMilliseconds ms waiting for a control-server reply."
    }
    $count = $read.GetAwaiter().GetResult()
    if ($count -eq 0) { break }
    $null = $builder.Append($buffer, 0, $count)
    if ($builder.Length -gt $MaximumBytes -or
        [Text.Encoding]::UTF8.GetByteCount($builder.ToString()) -gt $MaximumBytes) {
      throw "Control-server reply exceeds the $MaximumBytes-byte bound."
    }
  }
  $builder.ToString()
}

function Invoke-SoalCommand([string[]]$Parts) {
  $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
    '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
  $writer = $null
  $reader = $null
  try {
    $pipe.Connect($ConnectTimeoutMilliseconds)
    if ($ExpectedServerProcessId -gt 0) {
      try {
        [SoALCli.AuthenticatedPipe]::Verify(
            $pipe.SafePipeHandle, [uint32]$ExpectedServerProcessId,
            $ExpectedServerStartTimeUtcTicks, $ExpectedServerImagePath,
            $ExpectedServerUserSid)
      }
      catch {
        # This check is deliberately before StreamWriter construction and before request bytes.
        throw "SOAL_PIPE_IDENTITY_REJECTED: $($_.Exception.Message)"
      }
    }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $writer = [System.IO.StreamWriter]::new($pipe, $utf8, 1024, $true)
    $writer.AutoFlush = $true
    $reader = [System.IO.StreamReader]::new($pipe, $utf8, $false, 1024, $true)
    try {
      $writer.WriteLine(($Parts -join ' '))
      $raw = Read-BoundedPipeResponse -Reader $reader `
          -TimeoutMilliseconds $ResponseTimeoutMilliseconds -MaximumBytes $MaximumResponseBytes
      [SoALCli.StrictJsonGuard]::Validate($raw, $MaximumResponseBytes, 32, $MaximumJsonNodes)
    }
    catch {
      if ($_.Exception.Message -clike 'SOAL_CONTROL_PROTOCOL_REJECTED:*') { throw }
      throw "SOAL_CONTROL_PROTOCOL_REJECTED: $($_.Exception.Message)"
    }
    $raw
  }
  finally {
    if ($writer) { try { $writer.Dispose() } catch { } }
    if ($reader) { try { $reader.Dispose() } catch { } }
    try { $pipe.Dispose() } catch { }
  }
}

if ($Command[0] -ceq 'watch') {
  $target = if ($Command.Count -gt 1) { $Command[1] } else { 'state' }
  while ($true) {
    Invoke-SoalCommand @($target)
    Start-Sleep -Milliseconds 250
  }
}

if ($Command.Count -ge 2 -and $Command[0] -ceq 'dev' -and $Command[1] -ceq 'watch') {
  if ($Command.Count -ne 4) {
    throw 'Usage: soal-cli.ps1 [-WatchIntervalMilliseconds N] [-WatchPollCount N] dev watch <address|@symbol> <type>'
  }
  $readCommand = @('dev', 'read', $Command[2], $Command[3])
  $timer = [Diagnostics.Stopwatch]::StartNew()
  $lastKey = $null
  $poll = 0
  $sequence = 0
  while ($WatchPollCount -eq 0 -or $poll -lt $WatchPollCount) {
    $raw = Invoke-SoalCommand $readCommand
    try { $sample = $raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Control server returned invalid JSON: $raw" }
    $key = [ordered]@{
      ok = $sample.ok; error = $sample.error; address = $sample.address
      type = $sample.type; value_bits = $sample.value_bits
    } | ConvertTo-Json -Compress
    if ($null -eq $lastKey -or $key -cne $lastKey) {
      [ordered]@{
        watch_sequence = $sequence; watch_poll = $poll
        elapsed_ms = $timer.ElapsedMilliseconds; sample = $sample
      } | ConvertTo-Json -Compress -Depth 16
      $lastKey = $key
      $sequence++
    }
    $poll++
    if ($WatchPollCount -eq 0 -or $poll -lt $WatchPollCount) {
      Start-Sleep -Milliseconds $WatchIntervalMilliseconds
    }
  }
  return
}

Invoke-SoalCommand $Command
