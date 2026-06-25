namespace LoginActivityTriage.Tests;

/// <summary>
/// Representative event XML snippets used to exercise the normalisers. These
/// mirror the real Security-log schema (single-quoted attributes are valid XML
/// and keep the C# literals free of escaping).
/// </summary>
internal static class SampleEvents
{
    public const string Logon4624 = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime='2026-06-20T13:45:12.1234567Z'/>
    <EventRecordID>100245</EventRecordID>
    <Channel>Security</Channel>
    <Computer>HOST01.contoso.local</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>HOST01$</Data>
    <Data Name='TargetUserName'>jdoe</Data>
    <Data Name='TargetDomainName'>CONTOSO</Data>
    <Data Name='TargetUserSid'>S-1-5-21-111-222-333-1104</Data>
    <Data Name='LogonType'>10</Data>
    <Data Name='IpAddress'>10.20.30.40</Data>
    <Data Name='IpPort'>50912</Data>
    <Data Name='WorkstationName'>JUMPHOST</Data>
    <Data Name='AuthenticationPackageName'>Negotiate</Data>
    <Data Name='LogonProcessName'>User32 </Data>
    <Data Name='ElevatedToken'>%%1842</Data>
    <Data Name='ProcessName'>C:\Windows\System32\winlogon.exe</Data>
  </EventData>
</Event>";

    public const string Failed4625 = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime='2026-06-20T02:11:05.0000000Z'/>
    <EventRecordID>100300</EventRecordID>
    <Channel>Security</Channel>
    <Computer>HOST02</Computer>
  </System>
  <EventData>
    <Data Name='TargetUserName'>administrator</Data>
    <Data Name='TargetDomainName'>CONTOSO</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='IpAddress'>::ffff:203.0.113.7</Data>
    <Data Name='Status'>0xC000006D</Data>
    <Data Name='SubStatus'>0xC000006A</Data>
    <Data Name='AuthenticationPackageName'>NTLM</Data>
  </EventData>
</Event>";

    public const string Explicit4648 = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4648</EventID>
    <TimeCreated SystemTime='2026-06-20T09:30:00.0000000Z'/>
    <EventRecordID>100355</EventRecordID>
    <Channel>Security</Channel>
    <Computer>HOST01</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>jdoe</Data>
    <Data Name='TargetUserName'>svc_admin</Data>
    <Data Name='TargetServerName'>DC01</Data>
    <Data Name='ProcessName'>C:\Windows\System32\runas.exe</Data>
  </EventData>
</Event>";

    public const string Privileged4672 = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4672</EventID>
    <TimeCreated SystemTime='2026-06-20T13:45:12.5000000Z'/>
    <EventRecordID>100246</EventRecordID>
    <Channel>Security</Channel>
    <Computer>HOST01</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>jdoe</Data>
    <Data Name='SubjectDomainName'>CONTOSO</Data>
    <Data Name='PrivilegeList'>SeDebugPrivilege</Data>
  </EventData>
</Event>";

    // Missing TimeCreated, Ip, and most fields - must not throw.
    public const string SparseLogon = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><EventID>4624</EventID><Channel>Security</Channel></System>
  <EventData><Data Name='TargetUserName'>partial</Data></EventData>
</Event>";

    public const string Malformed = @"<Event><System><EventID>4624</EventID";

    public const string UnsupportedEvent = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><EventID>1102</EventID><Channel>Security</Channel>
  <TimeCreated SystemTime='2026-06-20T13:45:12Z'/></System>
  <EventData><Data Name='SubjectUserName'>jdoe</Data></EventData>
</Event>";
}
