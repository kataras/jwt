<#
.SYNOPSIS
  Finds the tells of AI-drafted prose in this repository's markdown.

.DESCRIPTION
  Fence aware: it never reports anything inside a fenced code block, and it blanks inline
  code spans, link targets and image targets before matching, so an identifier containing
  an underscore or a URL containing a double dash is not a finding.

  Exit code is 1 while findings remain and 0 when there are none. Zero is the bar for every
  tracked markdown file here.

.PARAMETER Path
  Files or directories to scan. Directories are walked for *.md.

.PARAMETER Md
  Scan the whole tracked markdown corpus: book/, brand/, skill/, and the root README and
  CHANGELOG.

.PARAMETER Summary
  Print one line per rule with a count, instead of one line per finding.

.PARAMETER Wrap
  Report files whose prose lines run past 100 columns, instead of scanning for tells.

.EXAMPLE
  pwsh skill/human-writing/scripts/scan-tells.ps1 book/03-claims.md

.EXAMPLE
  pwsh skill/human-writing/scripts/scan-tells.ps1 -Md
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]] $Path,
    [switch] $Md,
    [switch] $Summary,
    [switch] $Wrap,
    [int] $WrapAt = 100
)

$ErrorActionPreference = 'Stop'

# Repository root, two levels up from this script's directory.
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..' '..' '..')).Path

# The corpus. Keep this in step with the Scope section of SKILL.md: if the two ever
# disagree, one of them has a bug.
$corpus = @(
    'book',
    'brand',
    'skill',
    'README.md',
    'CHANGELOG.md'
)

$rules = @(
    @{ Name = 'em-dash';        Pattern = '—' }
    @{ Name = 'en-dash-prose';  Pattern = '(?<=[A-Za-z])\s–\s(?=[A-Za-z])' }
    @{ Name = 'ascii-dash';     Pattern = '(?<!\S)--(?=\s)' }
    @{ Name = 'contraction';    Pattern = "(?i)\b(don|doesn|didn|isn|aren|wasn|weren|can|couldn|won|wouldn|shouldn|hasn|haven|hadn|it|that|there|here|you|we|they|I|let|who|what)['’](t|s|re|ve|ll|d|m)\b" }
    @{ Name = 'buzzword';       Pattern = '(?i)\b(comprehensive|robust|seamless(ly)?|streamlined?|leverag(e|es|ed|ing)|utiliz(e|es|ed|ing)|facilitat(e|es|ed|ing)|delve|plethora|myriad|cutting-edge|industry-leading|effortless(ly)?|game-chang(ing|ers?)|blazing(ly)?[- ]fast|ever-evolving|state-of-the-art|battle-tested|testament to|tapestry|treasure trove|boast(s|ing)?|empower(s|ed|ing|ment)?|unleash(es|ed|ing)?|supercharge)\b' }
    @{ Name = 'soft-adjective'; Pattern = '(?i)\b(crucial|vital|powerful tool|essential tool|significantly improve|highly performant)\b' }
    @{ Name = 'not-just';       Pattern = "(?i)\b(isn['’]t just|is not just|not just a|not only .{1,40} but also|more than just)\b" }
    @{ Name = 'participial';    Pattern = '(?i),\s+(ensuring|allowing|enabling|empowering|making it|providing)\b' }
    @{ Name = 'dive';           Pattern = "(?i)\b(let['’]s dive|deep dive|dive into|dive deeper)\b" }
    @{ Name = 'template';       Pattern = '(?i)(provides? an? (robust|flexible|comprehensive|straightforward|simple|convenient|versatile)|walk you through|by (leveraging|understanding|utilizing)|you can ensure that|allows? (you|developers|users) to|allowing (you|developers) to|enables you to|makes it easy to|by following the steps outlined|we will (learn|explore|cover|see)|in this (tutorial|guide|article|document|documentation),? (we|you will))' }
    @{ Name = 'preamble';       Pattern = "(?i)(it is worth noting|it['’]s worth noting|^\s*(furthermore|moreover|additionally)\b|in conclusion|feel free to|as we have seen)" }
    @{ Name = 'section';        Pattern = '(?i)^\s*#{1,4}\s+(conclusion|introduction|overview|getting started with)\s*$' }
    @{ Name = 'admonition';     Pattern = '^\s*>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]' }
    @{ Name = 'emoji';          Pattern = '[←-⇿⌀-⏿☀-➿\uD83C-􏰀-\uDFFF️]' }
)

function Get-TargetFiles {
    $roots = if ($Md -or -not $Path) { $corpus | ForEach-Object { Join-Path $repo $_ } } else { $Path }

    $files = New-Object System.Collections.Generic.List[string]
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }

        $item = Get-Item $root
        if ($item.PSIsContainer) {
            Get-ChildItem -Path $root -Filter *.md -Recurse -File |
                Where-Object { $_.FullName -notmatch '\\output\\' } |
                ForEach-Object { $files.Add($_.FullName) }
        }
        elseif ($item.Extension -eq '.md') {
            $files.Add($item.FullName)
        }
    }

    return $files
}

# Blank out anything that is not prose, so a rule never fires on code or a URL.
function Clear-NonProse {
    param([string] $Line)

    $s = $Line
    # Multi-backtick spans first. A span written as ``like `this` `` contains single
    # backticks, so matching the single-backtick form first would leave its contents
    # exposed and report the punctuation inside it.
    $s = [regex]::Replace($s, '``.*?``', { ' ' * $args[0].Length })
    $s = [regex]::Replace($s, '`[^`]*`', { ' ' * $args[0].Length })          # inline code
    $s = [regex]::Replace($s, '\]\([^)]*\)', { ' ' * $args[0].Length })      # link and image targets
    $s = [regex]::Replace($s, '^\s{4,}\S.*$', { ' ' * $args[0].Length })     # indented code
    $s = [regex]::Replace($s, 'https?://\S+', { ' ' * $args[0].Length })     # bare URLs
    return $s
}

$files = Get-TargetFiles
if ($files.Count -eq 0) {
    Write-Host 'scan-tells: nothing to scan'
    exit 0
}

$findings = New-Object System.Collections.Generic.List[psobject]
$wrapFindings = New-Object System.Collections.Generic.List[psobject]

foreach ($file in $files) {
    $lines = Get-Content -LiteralPath $file
    $inFence = $false
    $inFrontMatter = $false
    $lineNo = 0

    foreach ($raw in $lines) {
        $lineNo++

        # YAML front matter is metadata, not prose. A skill's own description names the
        # words it exists to catch, and flagging that is noise rather than a finding.
        if ($lineNo -eq 1 -and $raw -eq '---') { $inFrontMatter = $true; continue }
        if ($inFrontMatter) {
            if ($raw -eq '---') { $inFrontMatter = $false }
            continue
        }

        if ($raw -match '^\s*(```|~~~)') {
            $inFence = -not $inFence
            continue
        }
        if ($inFence) { continue }

        $line = Clear-NonProse $raw

        if ($Wrap) {
            if ($raw.Length -gt $WrapAt) {
                $wrapFindings.Add([pscustomobject]@{
                    File = $file; Line = $lineNo; Width = $raw.Length
                })
            }
            continue
        }

        foreach ($rule in $rules) {
            foreach ($m in [regex]::Matches($line, $rule.Pattern)) {
                $findings.Add([pscustomobject]@{
                    File  = $file
                    Line  = $lineNo
                    Col   = $m.Index + 1
                    Rule  = $rule.Name
                    Text  = $raw.Trim()
                    Match = $m.Value
                })
            }
        }
    }
}

$rel = { param($p) $p.Replace($repo + [IO.Path]::DirectorySeparatorChar, '').Replace('\', '/') }

if ($Wrap) {
    foreach ($w in $wrapFindings) {
        '{0}:{1}: {2} columns' -f (& $rel $w.File), $w.Line, $w.Width | Write-Host
    }
    Write-Host ''
    Write-Host ("scan-tells: {0} lines over {1} columns in {2} files" -f $wrapFindings.Count, $WrapAt, $files.Count)
    exit ([int]($wrapFindings.Count -gt 0))
}

if ($Summary) {
    $findings | Group-Object Rule | Sort-Object Count -Descending | ForEach-Object {
        '{0,-16} {1}' -f $_.Name, $_.Count | Write-Host
    }
}
else {
    foreach ($f in $findings) {
        '{0}:{1}:{2}: {3}: {4}' -f (& $rel $f.File), $f.Line, $f.Col, $f.Rule, $f.Match | Write-Host
        '    {0}' -f $f.Text | Write-Host
    }
}

Write-Host ''
Write-Host ("scan-tells: {0} findings in {1} files" -f $findings.Count, $files.Count)
exit ([int]($findings.Count -gt 0))
