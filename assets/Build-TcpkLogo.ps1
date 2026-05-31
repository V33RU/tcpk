#requires -Version 5.1
<#
  Generates TCPK brand assets from the approved logo design (flat vector recreation):
    tcpk-mark.png   256x256  the windowed-reticle mark (transparent)
    tcpk-logo.png   1000x300 full horizontal lockup (mark + >. TCPK + tagline)
    tcpk-badge.png  340x360  vertical lockup (mark over TCPK over tagline)
    tcpk.ico        multi-size icon (16/32/48/64/128/256) for the EXE + window

  Re-run any time:  powershell -ExecutionPolicy Bypass -File assets\Build-TcpkLogo.ps1
  To use your OWN exact PNG instead, just replace tcpk-logo.png / tcpk-mark.png
  in this folder -- the GUI and report load these files at runtime.
#>
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# brand palette (sampled from the supplied logo)
$GRAY  = [System.Drawing.Color]::FromArgb(202,207,212)
$GRAYD = [System.Drawing.Color]::FromArgb(150,156,162)
$BLUE  = [System.Drawing.Color]::FromArgb(43,124,201)
$GREEN = [System.Drawing.Color]::FromArgb(67,160,71)
$TAG   = [System.Drawing.Color]::FromArgb(196,201,206)

function Get-RoundRect([single]$x,[single]$y,[single]$w,[single]$h,[single]$r){
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r*2
    $p.AddArc($x,$y,$d,$d,180,90)
    $p.AddArc($x+$w-$d,$y,$d,$d,270,90)
    $p.AddArc($x+$w-$d,$y+$h-$d,$d,$d,0,90)
    $p.AddArc($x,$y+$h-$d,$d,$d,90,90)
    $p.CloseFigure()
    return $p
}
function New-Pen($c,[single]$w){
    $pen = New-Object System.Drawing.Pen($c,$w)
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    return $pen
}

function Draw-Mark($g,[int]$S){
    $f = $S/256.0
    $CX = 128.0*$f; $CY = 130.0*$f
    # window frame
    $wp = New-Pen $GRAY ([single](11*$f))
    $rect = Get-RoundRect ([single](44*$f)) ([single](60*$f)) ([single](168*$f)) ([single](140*$f)) ([single](16*$f))
    $g.DrawPath($wp,$rect); $rect.Dispose(); $wp.Dispose()
    # title squares
    $gb = New-Object System.Drawing.SolidBrush($GRAY)
    foreach($sx in 58,74,90){ $g.FillRectangle($gb,[single]($sx*$f),[single](70*$f),[single](9*$f),[single](9*$f)) }
    # reticle ring
    $rp = New-Pen $GRAY ([single](8*$f))
    $g.DrawEllipse($rp,[single](($CX/$f-38)*$f),[single](($CY/$f-38)*$f),[single](76*$f),[single](76*$f)); $rp.Dispose()
    # vertical crosshair (gap at centre)
    $cp = New-Pen $GRAY ([single](8*$f))
    $g.DrawLine($cp,$CX,[single](78*$f),$CX,[single](118*$f))
    $g.DrawLine($cp,$CX,[single](142*$f),$CX,[single](190*$f)); $cp.Dispose()
    # horizontal scan line: blue / green | green / blue
    $bp = New-Pen $BLUE ([single](8*$f)); $gp = New-Pen $GREEN ([single](8*$f))
    $g.DrawLine($bp,[single](6*$f),$CY,[single](56*$f),$CY)
    $g.DrawLine($gp,[single](70*$f),$CY,[single](110*$f),$CY)
    $g.DrawLine($gp,[single](146*$f),$CY,[single](186*$f),$CY)
    $g.DrawLine($bp,[single](200*$f),$CY,[single](250*$f),$CY)
    $bp.Dispose(); $gp.Dispose()
    # centre dot
    $g.FillEllipse($gb,[single]($CX-9*$f),[single]($CY-9*$f),[single](18*$f),[single](18*$f))
    $gb.Dispose()
}

function New-MarkBitmap([int]$S){
    $bmp = New-Object System.Drawing.Bitmap($S,$S)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)
    Draw-Mark $g $S
    $g.Dispose()
    return $bmp
}

function Draw-Prompt($g,[single]$x,[single]$yTop,[single]$scale){
    # ">" chevron (blue) + green square == the >_ prompt glyph
    $cp = New-Pen $BLUE ([single](16*$scale))
    $pts = @(
        (New-Object System.Drawing.PointF([single]$x,[single]($yTop))),
        (New-Object System.Drawing.PointF([single]($x+44*$scale),[single]($yTop+42*$scale))),
        (New-Object System.Drawing.PointF([single]$x,[single]($yTop+84*$scale)))
    )
    $g.DrawLines($cp,$pts); $cp.Dispose()
    $sq = New-Object System.Drawing.SolidBrush($GREEN)
    $g.FillRectangle($sq,[single]($x+52*$scale),[single]($yTop+60*$scale),[single](34*$scale),[single](34*$scale))
    $sq.Dispose()
}

function Save-Png($bmp,$name){
    $path = Join-Path $here $name
    $bmp.Save($path,[System.Drawing.Imaging.ImageFormat]::Png)
    Write-Host ("  {0}  {1}x{2}" -f $name,$bmp.Width,$bmp.Height)
}

# ---------- tcpk-mark.png ----------
$mark = New-MarkBitmap 256
Save-Png $mark 'tcpk-mark.png'

# ---------- tcpk-logo.png (horizontal lockup) ----------
$logo = New-Object System.Drawing.Bitmap(1000,300)
$g = [System.Drawing.Graphics]::FromImage($logo)
$g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'AntiAliasGridFit'
$g.Clear([System.Drawing.Color]::Transparent)
$m240 = New-MarkBitmap 240
$g.DrawImage($m240,[single]8,[single]30,[single]240,[single]240)
Draw-Prompt $g 296 108 1.0
$fontBig = New-Object System.Drawing.Font('Segoe UI',120,[System.Drawing.FontStyle]::Bold,[System.Drawing.GraphicsUnit]::Pixel)
$rfill = New-Object System.Drawing.RectangleF(405,60,560,200)
$grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rfill,$GRAY,$GRAYD,90.0)
$g.DrawString('TCPK',$fontBig,$grad,[single]400,[single]58)
$fontTag = New-Object System.Drawing.Font('Segoe UI',30,[System.Drawing.FontStyle]::Regular,[System.Drawing.GraphicsUnit]::Pixel)
$tagBrush = New-Object System.Drawing.SolidBrush($TAG)
$g.DrawString('Find.   Verify.   Report.',$fontTag,$tagBrush,[single]410,[single]232)
$g.Dispose(); Save-Png $logo 'tcpk-logo.png'

# ---------- tcpk-badge.png (vertical lockup) ----------
$badge = New-Object System.Drawing.Bitmap(340,360)
$g = [System.Drawing.Graphics]::FromImage($badge)
$g.SmoothingMode='AntiAlias'; $g.TextRenderingHint='AntiAliasGridFit'
$g.Clear([System.Drawing.Color]::Transparent)
$m200 = New-MarkBitmap 200
$g.DrawImage($m200,[single]70,[single]4,[single]200,[single]200)
$fontMid = New-Object System.Drawing.Font('Segoe UI',74,[System.Drawing.FontStyle]::Bold,[System.Drawing.GraphicsUnit]::Pixel)
$sz = $g.MeasureString('TCPK',$fontMid)
$rfill2 = New-Object System.Drawing.RectangleF(0,210,340,90)
$grad2 = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rfill2,$GRAY,$GRAYD,90.0)
$g.DrawString('TCPK',$fontMid,$grad2,[single]((340-$sz.Width)/2),[single]212)
$fontTag2 = New-Object System.Drawing.Font('Segoe UI',19,[System.Drawing.FontStyle]::Regular,[System.Drawing.GraphicsUnit]::Pixel)
$tb2 = New-Object System.Drawing.SolidBrush($TAG)
$tsz = $g.MeasureString('Find. Verify. Report.',$fontTag2)
$g.DrawString('Find. Verify. Report.',$fontTag2,$tb2,[single]((340-$tsz.Width)/2),[single]308)
$g.Dispose(); Save-Png $badge 'tcpk-badge.png'

# ---------- tcpk.ico (multi-size) ----------
$icoPath = Join-Path $here 'tcpk.ico'
$sizes = 16,24,32,48,64,128,256
$blobs = @()
foreach($s in $sizes){
    $b = New-MarkBitmap $s
    $ms = New-Object System.IO.MemoryStream
    $b.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png)
    $blobs += ,([byte[]]$ms.ToArray())
    $ms.Dispose(); $b.Dispose()
}
$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16*$sizes.Count
for($i=0; $i -lt $sizes.Count; $i++){
    $s = $sizes[$i]; $len = $blobs[$i].Length
    $dim = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim)
    $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$len); $bw.Write([uint32]$offset)
    $offset += $len
}
foreach($b in $blobs){ $bw.Write($b) }
$bw.Flush(); $bw.Close(); $fs.Close()
Write-Host ("  tcpk.ico  ({0} sizes, {1} bytes)" -f $sizes.Count, (Get-Item $icoPath).Length)

Write-Host "TCPK logo assets generated in: $here"
