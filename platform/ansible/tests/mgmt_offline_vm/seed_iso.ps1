param(
    [Parameter(Mandatory = $true)][string]$SeedDir,
    [Parameter(Mandatory = $true)][string]$IsoPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $SeedDir -PathType Container)) {
    throw 'NoCloud seed directory is missing'
}
if (Test-Path -LiteralPath $IsoPath) {
    throw 'Refuse to replace an existing NoCloud ISO'
}
$names = @(Get-ChildItem -LiteralPath $SeedDir -File | ForEach-Object Name | Sort-Object)
if (($names -join ',') -ne 'meta-data,network-config,user-data') {
    throw 'NoCloud seed must contain only meta-data, network-config and user-data'
}

# PowerShell cannot invoke the returned COM IStream directly. The typed C# cast
# performs QueryInterface and lets us verify every byte read from the image.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class EcommerceNoCloudIsoWriter
{
    public static void Save(object imageStream, string path, long expectedBytes)
    {
        if (expectedBytes < 32768 || expectedBytes > 16777216)
            throw new InvalidDataException("NoCloud ISO size is outside the bounded fixture range");
        IStream input = (IStream)imageStream;
        IntPtr count = Marshal.AllocCoTaskMem(sizeof(int));
        byte[] buffer = new byte[65536];
        try
        {
            using (FileStream output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                long remaining = expectedBytes;
                while (remaining > 0)
                {
                    int requested = (int)Math.Min(buffer.Length, remaining);
                    Marshal.WriteInt32(count, 0);
                    input.Read(buffer, requested, count);
                    int actual = Marshal.ReadInt32(count);
                    if (actual != requested)
                        throw new EndOfStreamException("IMAPI2FS returned a truncated ISO image");
                    output.Write(buffer, 0, actual);
                    remaining -= actual;
                }
                output.Flush(true);
            }
        }
        finally
        {
            Marshal.FreeCoTaskMem(count);
        }
    }
}
'@

$image = $null
$result = $null
$stream = $null
try {
    $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $image.VolumeName = 'CIDATA'
    # ISO9660 + Joliet preserves NoCloud's lower-case hyphenated file names.
    $image.FileSystemsToCreate = 3
    $image.Root.AddTree($SeedDir, $false)
    $result = $image.CreateResultImage()
    $stream = $result.ImageStream
    $size = [long]$result.TotalBlocks * [long]$result.BlockSize
    [EcommerceNoCloudIsoWriter]::Save($stream, $IsoPath, $size)
}
finally {
    if ($null -ne $stream) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($stream) }
    if ($null -ne $result) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($result) }
    if ($null -ne $image) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($image) }
}
