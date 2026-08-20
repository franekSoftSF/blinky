<#
.SYNOPSIS
    Builds multi-resolution .ico files from the 256px branding artwork.

.DESCRIPTION
    The hand-made .ico files in assets/branding hold a single 256x256 image.
    Windows will happily use one for a 16x16 tray icon and the result is a
    blurred smudge next to crisp system icons - the one place this icon is seen
    most often is the one place a single large image looks worst.

    This writes every size Windows actually asks for. PNG payloads throughout,
    which Windows has understood since Vista and which keeps the file small.
#>

[CmdletBinding()]
param(
    [string] $Source = "$PSScriptRoot\..\assets\branding",
    [int[]] $Sizes = @(16, 20, 24, 32, 48, 64, 128, 256)
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

function Write-Icon {
    param([string] $Name)

    $sourceFile = Join-Path $Source "$Name-256.png"
    $target = Join-Path $Source "$Name.ico"

    if (-not (Test-Path $sourceFile)) {
        Write-Warning "no $sourceFile - skipping"
        return
    }

    $original = [System.Drawing.Image]::FromFile((Resolve-Path $sourceFile))
    $payloads = @()

    try {
        foreach ($size in $Sizes) {
            $bitmap = New-Object System.Drawing.Bitmap($size, $size)
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)

            # Bicubic with high-quality pixel offset: the default nearest
            # neighbour turns a 256px drawing into aliased confetti at 16px.
            $graphics.InterpolationMode = 'HighQualityBicubic'
            $graphics.SmoothingMode = 'AntiAlias'
            $graphics.PixelOffsetMode = 'HighQuality'
            $graphics.Clear([System.Drawing.Color]::Transparent)
            $graphics.DrawImage($original, 0, 0, $size, $size)
            $graphics.Dispose()

            $stream = New-Object System.IO.MemoryStream
            $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
            $bitmap.Dispose()

            $payloads += , @{ Size = $size; Bytes = $stream.ToArray() }
            $stream.Dispose()
        }
    }
    finally {
        $original.Dispose()
    }

    $out = [System.IO.File]::Create($target)
    $writer = New-Object System.IO.BinaryWriter($out)

    try {
        # ICONDIR: reserved, type 1 (icon), count.
        $writer.Write([uint16]0)
        $writer.Write([uint16]1)
        $writer.Write([uint16]$payloads.Count)

        # Directory entries come first, so every offset has to account for all
        # of them: six bytes of header plus sixteen per entry.
        $offset = 6 + (16 * $payloads.Count)

        foreach ($payload in $payloads) {
            # 256 is written as 0 - the field is one byte, and that is how the
            # format has always said "the big one".
            $dimension = if ($payload.Size -ge 256) { 0 } else { $payload.Size }

            $writer.Write([byte]$dimension)
            $writer.Write([byte]$dimension)
            $writer.Write([byte]0)      # palette entries, none for PNG
            $writer.Write([byte]0)      # reserved
            $writer.Write([uint16]1)    # colour planes
            $writer.Write([uint16]32)   # bits per pixel
            $writer.Write([uint32]$payload.Bytes.Length)
            $writer.Write([uint32]$offset)

            $offset += $payload.Bytes.Length
        }

        foreach ($payload in $payloads) {
            $writer.Write($payload.Bytes)
        }
    }
    finally {
        $writer.Dispose()
        $out.Dispose()
    }

    $sizes = ($payloads | ForEach-Object { $_.Size }) -join ', '
    Write-Host "  $target  ($sizes)"
}

Write-Host "building icons ..."
Write-Icon -Name 'blinky-agent'
Write-Icon -Name 'blinky-server'
