using System.Diagnostics.Eventing.Reader;
using System.IO;
using LoginActivityTriage.Parsing;
using Xunit;

namespace LoginActivityTriage.Tests;

/// <summary>
/// EVTX files past MAX_PATH (0.3.0). Velociraptor / KAPE trees put Security.evtx well past 260
/// characters; the Windows event log API failed every such file with status 3 ("cannot find the
/// path") and the run ended "None of the input logs could be read" (exit 4).
/// </summary>
public class LongPathTests
{
    [Fact]
    public void ApiPath_LeavesShortPathsAlone()
    {
        Assert.Equal(@"C:\Cases\HOST01\Security.evtx", EvtxFileReader.ApiPath(@"C:\Cases\HOST01\Security.evtx"));
        Assert.Equal(@"\\?\C:\x\Security.evtx", EvtxFileReader.ApiPath(@"\\?\C:\x\Security.evtx"));
    }

    [Fact]
    public void ApiPath_UsesTheExtendedLengthFormPastMaxPath()
    {
        var local = @"C:\Cases\" + new string('x', 250) + @"\Security.evtx";
        Assert.Equal(@"\\?\" + local, EvtxFileReader.ApiPath(local));
        var unc = @"\\server\share\" + new string('y', 250) + @"\Security.evtx";
        Assert.Equal(@"\\?\UNC\server\share\" + new string('y', 250) + @"\Security.evtx", EvtxFileReader.ApiPath(unc));
    }

    [Fact]
    public void AnEvtxPastMaxPath_IsImported()
    {
        var dir = Path.Combine(Path.GetTempPath(), "lat-tests-" + Guid.NewGuid().ToString("N"));
        var tail = Path.Combine("Collection-TESTHOST-2026-10-04T00_00_00Z", "uploads", "auto", "C%3A",
            "Windows", "System32", "winevt", "Logs");
        var pad = new string('x', Math.Max(1, 280 - Path.Combine(dir, "p", tail, "Application.evtx").Length));
        var logs = Path.Combine(dir, pad, tail);
        Directory.CreateDirectory(logs);
        try
        {
            // A few records of this machine's Application log (readable without elevation).
            long first;
            using (var r = new EventLogReader(new EventLogQuery("Application", PathType.LogName)))
            using (var rec = r.ReadEvent())
            {
                Assert.NotNull(rec);
                first = rec!.RecordId ?? 0;
            }
            var shortCopy = Path.Combine(dir, "small.evtx");
            EventLogSession.GlobalSession.ExportLog("Application", PathType.LogName,
                $"*[System[(EventRecordID>={first} and EventRecordID<{first + 20})]]", shortCopy);
            var longCopy = Path.Combine(logs, "Application.evtx");
            File.Copy(shortCopy, longCopy);
            Assert.True(longCopy.Length >= 260, $"test path is only {longCopy.Length} characters");

            var reader = new EvtxFileReader();
            var expected = reader.Read(shortCopy).Count();
            Assert.True(expected > 0);
            Assert.Equal(expected, reader.Read(longCopy).Count());

            // The CLI path: discover the folder, import it. Only wanted event ids count as read.
            var summary = new EvtxImporter().Import(logs, _ => { });
            Assert.Equal(0, summary.FilesFailed);
            Assert.False(summary.Files[0].Failed, summary.Files[0].Error);
            Assert.Equal(longCopy, summary.Files[0].FilePath);   // recorded as the plain path, not \\?\
            Assert.Equal(new EvtxImporter().Import(shortCopy, _ => { }).Files[0].RecordsRead, summary.Files[0].RecordsRead);
            Assert.Equal("TESTHOST", summary.Files[0].Hostname);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }
}
