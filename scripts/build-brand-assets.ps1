Add-Type -AssemblyName System.Drawing
$projectRoot = Split-Path $PSScriptRoot -Parent
$brandRoot = Join-Path $projectRoot 'desktop'
New-Item -ItemType Directory -Path $brandRoot -Force | Out-Null
function Draw-Mark($canvas, $x, $y, $size) {
    $brush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(83,184,158))
    $canvas.FillEllipse($brush, $x, $y, $size, $size)
    $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(13,25,21), $size * 0.075)
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
    $canvas.DrawLine($pen, [single]($x+$size*.32), [single]($y+$size*.68), [single]($x+$size*.67), [single]($y+$size*.33))
    $canvas.DrawLine($pen, [single]($x+$size*.36), [single]($y+$size*.33), [single]($x+$size*.67), [single]($y+$size*.33))
    $canvas.DrawLine($pen, [single]($x+$size*.67), [single]($y+$size*.33), [single]($x+$size*.67), [single]($y+$size*.64))
    $pen.Dispose(); $brush.Dispose()
}
$icon = [System.Drawing.Bitmap]::new(256,256)
$graphics = [System.Drawing.Graphics]::FromImage($icon)
$graphics.SmoothingMode = 'AntiAlias'
Draw-Mark $graphics 8 8 240
$stream = [System.IO.MemoryStream]::new()
$icon.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
$png = $stream.ToArray()
$icoStream = [System.IO.File]::Create((Join-Path $brandRoot 'icon.ico'))
$writer = [System.IO.BinaryWriter]::new($icoStream)
$writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]1)
$writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0)
$writer.Write([uint16]1); $writer.Write([uint16]32); $writer.Write([uint32]$png.Length); $writer.Write([uint32]22); $writer.Write($png)
$writer.Dispose(); $stream.Dispose(); $graphics.Dispose(); $icon.Dispose()
$sidebar = [System.Drawing.Bitmap]::new(164,314)
$canvas = [System.Drawing.Graphics]::FromImage($sidebar)
$canvas.SmoothingMode = 'AntiAlias'
$canvas.Clear([System.Drawing.Color]::FromArgb(19,20,24))
$grid = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(34,43,40))
for ($i=0; $i -lt 314; $i+=32) { $canvas.DrawLine($grid,0,$i,164,$i) }
for ($i=0; $i -lt 164; $i+=32) { $canvas.DrawLine($grid,$i,0,$i,314) }
Draw-Mark $canvas 22 28 50
$white = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(234,237,241))
$muted = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(150,167,158))
$titleFont = [System.Drawing.Font]::new('Segoe UI',18,[System.Drawing.FontStyle]::Bold)
$bodyFont = [System.Drawing.Font]::new('Segoe UI',9)
$canvas.DrawString('DropSync',$titleFont,$white,18,96)
$canvas.DrawString("Your devices.`nCloser together.",$bodyFont,$muted,20,139)
$canvas.DrawString("PRIVATE BY DESIGN`n`nLOCAL FIRST",$bodyFont,$muted,20,246)
$sidebar.Save((Join-Path $brandRoot 'installer-sidebar.bmp'),[System.Drawing.Imaging.ImageFormat]::Bmp)
$canvas.Dispose(); $sidebar.Dispose(); $grid.Dispose(); $white.Dispose(); $muted.Dispose(); $titleFont.Dispose(); $bodyFont.Dispose()
