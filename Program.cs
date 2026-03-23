
using System;
using System.DirectoryServices;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

class Program
{
    private const int BannerInnerWidth = 118;
    private const int WmSetIcon = 0x0080;
    private static readonly Guid ForceChangePasswordGuid = new Guid("00299570-246d-11d0-a768-00aa006e0529");
    private static readonly Guid SelfMembershipGuid = new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2");
    private static readonly IntPtr IconBig = new IntPtr(1);
    private static readonly IntPtr IconSmall = IntPtr.Zero;
    private static IntPtr _iconHandle = IntPtr.Zero;

    static int Main(string[] args)
    {
        PrintBanner();
        TryApplyConsoleIcon();

        while (true)
        {
            PrintOptions();
            WritePrompt("Select option [1/2/Q]: ");
            string option = Console.ReadLine();
            if (option == null)
            {
                WriteError("Input stream error: Input stream is not available.");
                return 1;
            }

            option = option.Trim();
            if (option.Equals("Q", StringComparison.OrdinalIgnoreCase))
            {
                WriteInfo("Exiting ACL scaner.");
                return 0;
            }

            if (option != "1" && option != "2")
            {
                WriteWarning("Invalid option. Choose 1, 2, or Q.");
                Console.WriteLine();
                continue;
            }

            string domainName;
            string targetName;
            try
            {
                WritePrompt("Enter the domain name (e.g., yourdomain.com): ");
                domainName = ReadRequiredInput();

                if (option == "1")
                {
                    WritePrompt("Enter target user/object (source principal): ");
                }
                else
                {
                    WritePrompt("Enter target user/object (destination object): ");
                }

                targetName = ReadRequiredInput();
            }
            catch (ArgumentException ex)
            {
                WriteWarning($"Input error: {ex.Message}");
                Console.WriteLine();
                continue;
            }
            catch (InvalidOperationException ex)
            {
                WriteError($"Input stream error: {ex.Message}");
                return 1;
            }

            string domainPath;
            try
            {
                domainPath = BuildLdapDomainPath(domainName);
            }
            catch (ArgumentException ex)
            {
                WriteWarning($"Invalid domain name: {ex.Message}");
                Console.WriteLine();
                continue;
            }

            try
            {
                string outputFilePath;
                bool exported = option == "1"
                    ? ExportInterestingPermissionsHeldByPrincipal(domainPath, targetName, out outputFilePath)
                    : ExportInterestingPermissionsOnTargetObject(domainPath, targetName, out outputFilePath);

                if (!exported)
                {
                    WriteWarning("Target user/object not found.");
                    Console.WriteLine();
                    continue;
                }

                Console.WriteLine();
                WriteSuccess($"Output saved to: {outputFilePath}");
                Console.WriteLine();
            }
            catch (DirectoryServicesCOMException ex)
            {
                WriteError($"Active Directory query failed: {ex.Message}");
                Console.WriteLine();
            }
            catch (UnauthorizedAccessException ex)
            {
                WriteError($"Permission error: {ex.Message}");
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                WriteError($"Unexpected error: {ex.Message}");
                Console.WriteLine();
            }
        }
    }

    private static void PrintBanner()
    {
        ConsoleColor originalColor = Console.ForegroundColor;

        PrintBannerBorder();
        PrintBannerLine(string.Empty, ConsoleColor.DarkCyan);
        PrintBannerLine("ACL scaner v1.2", ConsoleColor.Cyan);
        PrintBannerLine("Built by Majid alkindi", ConsoleColor.Yellow);
        PrintBannerLine(string.Empty, ConsoleColor.DarkCyan);
        PrintBannerLine("This tool exports detailed Active Directory ACL data", ConsoleColor.Gray);
        PrintBannerLine("using domain lookup, user search, and access rule reporting", ConsoleColor.Gray);
        PrintBannerLine(string.Empty, ConsoleColor.DarkCyan);
        PrintBannerBorder();

        Console.ForegroundColor = originalColor;
        Console.WriteLine();
    }

    private static void PrintBannerBorder()
    {
        ConsoleColor originalColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.WriteLine(new string('-', BannerInnerWidth + 2));
        Console.ForegroundColor = originalColor;
    }

    private static void PrintBannerLine(string content, ConsoleColor textColor)
    {
        ConsoleColor originalColor = Console.ForegroundColor;

        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.Write("|");

        Console.ForegroundColor = textColor;
        Console.Write(CenterText(content, BannerInnerWidth));

        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.WriteLine("|");

        Console.ForegroundColor = originalColor;
    }

    private static string CenterText(string content, int width)
    {
        string value = content ?? string.Empty;
        if (value.Length >= width)
        {
            return value.Substring(0, width);
        }

        int totalPadding = width - value.Length;
        int leftPadding = totalPadding / 2;
        int rightPadding = totalPadding - leftPadding;
        return new string(' ', leftPadding) + value + new string(' ', rightPadding);
    }

    private static void PrintOptions()
    {
        ConsoleColor originalColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("Options:");
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine("  [1] Find where target user/object has interesting permissions on other domain objects");
        Console.WriteLine("  [2] Find who has interesting permissions on a target user/object");
        Console.WriteLine("  [Q] Press Ctrl+C to quit");
        Console.WriteLine();
        Console.ForegroundColor = originalColor;
    }

    private static void WritePrompt(string message)
    {
        ConsoleColor originalColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write(message);
        Console.ForegroundColor = originalColor;
    }

    private static void WriteInfo(string message)
    {
        WriteColoredLine(message, ConsoleColor.Gray);
    }

    private static void WriteSuccess(string message)
    {
        WriteColoredLine(message, ConsoleColor.Green);
    }

    private static void WriteWarning(string message)
    {
        WriteColoredLine(message, ConsoleColor.DarkYellow);
    }

    private static void WriteError(string message)
    {
        WriteColoredLine(message, ConsoleColor.Red);
    }

    private static void WriteColoredLine(string message, ConsoleColor color)
    {
        ConsoleColor originalColor = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(message);
        Console.ForegroundColor = originalColor;
    }

    private static bool ExportUserAcl(string domainPath, string userName, out string outputFilePath)
    {
        AuthorizationRuleCollection rules;
        if (!TryGetUserAccessRules(domainPath, userName, out rules))
        {
            outputFilePath = string.Empty;
            return false;
        }

        string safeFileStem = MakeSafeFileName(userName);
        string fileName = $"{safeFileStem}_acl_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
        outputFilePath = Path.Combine(Environment.CurrentDirectory, fileName);
        WriteVerbose($"Writing ACL report to: {outputFilePath}");

        using (StreamWriter writer = new StreamWriter(outputFilePath, false, Encoding.UTF8))
        {
            int totalRules = rules.Count;
            int processedRules = 0;
            int writtenRules = 0;

            WriteReportHeader(writer, userName, domainPath, totalRules);

            WriteProgressHeader(totalRules);
            foreach (AuthorizationRule rule in rules)
            {
                processedRules++;
                ActiveDirectoryAccessRule adRule = rule as ActiveDirectoryAccessRule;
                WriteProgress(processedRules, totalRules);

                if (adRule == null)
                {
                    continue;
                }

                writtenRules++;
                WriteRuleBlock(writer, writtenRules, adRule);
            }

            if (writtenRules == 0)
            {
                writer.WriteLine("No access rules were returned for this user.");
            }

            writer.WriteLine();
            writer.WriteLine(new string('=', 92));
            writer.WriteLine($"Export summary: {writtenRules} ACL rule(s) written.");

            WriteProgressCompleted(totalRules);
        }

        WriteVerbose("ACL export finished successfully.");
        return true;
    }

    private static bool ExportInterestingPermissionsHeldByPrincipal(string domainPath, string principalName, out string outputFilePath)
    {
        string principalPath;
        string principalDn;
        string resolvedName;
        string principalSam;
        string principalSid;
        if (!TryResolveDirectoryObject(domainPath, principalName, out principalPath, out principalDn, out resolvedName, out principalSam, out principalSid))
        {
            outputFilePath = string.Empty;
            return false;
        }

        string safeFileStem = MakeSafeFileName(principalName);
        string fileName = $"{safeFileStem}_interesting_permissions_as_source_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
        outputFilePath = Path.Combine(Environment.CurrentDirectory, fileName);
        WriteVerbose($"Writing source-permissions report to: {outputFilePath}");

        using (DirectoryEntry rootEntry = new DirectoryEntry(domainPath))
        using (DirectorySearcher searcher = new DirectorySearcher(rootEntry))
        using (StreamWriter writer = new StreamWriter(outputFilePath, false, Encoding.UTF8))
        {
            searcher.SearchScope = SearchScope.Subtree;
            searcher.PageSize = 500;
            searcher.Filter = "(objectClass=*)";
            searcher.PropertiesToLoad.Add("distinguishedName");
            searcher.PropertiesToLoad.Add("name");

            using (SearchResultCollection results = searcher.FindAll())
            {
                int totalObjects = results.Count;
                int processedObjects = 0;
                int skippedObjects = 0;
                int interestingRules = 0;

                WriteInterestingSourceReportHeader(writer, principalName, resolvedName, principalDn, domainPath, totalObjects);
                WriteProgressHeader(totalObjects);

                foreach (SearchResult result in results)
                {
                    processedObjects++;
                    WriteProgress(processedObjects, totalObjects);

                    string targetDn = GetSearchResultProperty(result, "distinguishedName");
                    string targetName = GetSearchResultProperty(result, "name");

                    try
                    {
                        using (DirectoryEntry targetEntry = result.GetDirectoryEntry())
                        {
                            ActiveDirectorySecurity security = targetEntry.ObjectSecurity;
                            AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(NTAccount));

                            foreach (AuthorizationRule rule in rules)
                            {
                                ActiveDirectoryAccessRule adRule = rule as ActiveDirectoryAccessRule;
                                if (adRule == null)
                                {
                                    continue;
                                }

                                string matchedPermissions;
                                if (!IsInterestingPermission(adRule, out matchedPermissions))
                                {
                                    continue;
                                }

                                if (!RuleMatchesPrincipal(adRule, principalName, resolvedName, principalSam, principalSid))
                                {
                                    continue;
                                }

                                interestingRules++;
                                writer.WriteLine($"[Interesting Rule {interestingRules}]");
                                WriteReportField(writer, "Source Principal", adRule.IdentityReference.Value);
                                WriteReportField(writer, "Target Object Name", string.IsNullOrEmpty(targetName) ? "N/A" : targetName);
                                WriteReportField(writer, "Target Object DN", string.IsNullOrEmpty(targetDn) ? "N/A" : targetDn);
                                WriteReportField(writer, "Access Type", adRule.AccessControlType.ToString());
                                WriteReportField(writer, "Matched Permissions", matchedPermissions);
                                WriteReportField(writer, "AD Rights", adRule.ActiveDirectoryRights.ToString());
                                WriteReportField(writer, "Object Type", FormatGuidValue(adRule.ObjectType));
                                WriteReportField(writer, "Inherited Object Type", FormatGuidValue(adRule.InheritedObjectType));
                                writer.WriteLine(new string('-', 92));
                                writer.WriteLine();
                                WriteInterestingRuleConsole(
                                    interestingRules,
                                    adRule.IdentityReference.Value,
                                    string.IsNullOrEmpty(targetName) ? "N/A" : targetName,
                                    string.IsNullOrEmpty(targetDn) ? "N/A" : targetDn,
                                    matchedPermissions,
                                    adRule.AccessControlType.ToString());
                            }
                        }
                    }
                    catch
                    {
                        skippedObjects++;
                    }
                }

                if (interestingRules == 0)
                {
                    writer.WriteLine("No interesting permissions found where this principal has rights on other objects.");
                    writer.WriteLine();
                }

                writer.WriteLine(new string('=', 92));
                writer.WriteLine($"Objects processed : {processedObjects}");
                writer.WriteLine($"Objects skipped   : {skippedObjects}");
                writer.WriteLine($"Interesting rules : {interestingRules}");
                WriteProgressCompleted(totalObjects);
            }
        }

        WriteVerbose("Source-permissions analysis completed.");
        return true;
    }

    private static bool ExportInterestingPermissionsOnTargetObject(string domainPath, string targetObjectName, out string outputFilePath)
    {
        string targetPath;
        string targetDn;
        string resolvedName;
        string targetSam;
        string targetSid;
        if (!TryResolveDirectoryObject(domainPath, targetObjectName, out targetPath, out targetDn, out resolvedName, out targetSam, out targetSid))
        {
            outputFilePath = string.Empty;
            return false;
        }

        string safeFileStem = MakeSafeFileName(targetObjectName);
        string fileName = $"{safeFileStem}_interesting_permissions_on_target_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
        outputFilePath = Path.Combine(Environment.CurrentDirectory, fileName);
        WriteVerbose($"Writing target-object report to: {outputFilePath}");

        using (DirectoryEntry targetEntry = new DirectoryEntry(targetPath))
        using (StreamWriter writer = new StreamWriter(outputFilePath, false, Encoding.UTF8))
        {
            ActiveDirectorySecurity security = targetEntry.ObjectSecurity;
            AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(NTAccount));

            int totalRules = rules.Count;
            int processedRules = 0;
            int interestingRules = 0;

            WriteInterestingTargetReportHeader(writer, targetObjectName, resolvedName, targetDn, domainPath, totalRules);
            WriteProgressHeader(totalRules);

            foreach (AuthorizationRule rule in rules)
            {
                processedRules++;
                WriteProgress(processedRules, totalRules);

                ActiveDirectoryAccessRule adRule = rule as ActiveDirectoryAccessRule;
                if (adRule == null)
                {
                    continue;
                }

                string matchedPermissions;
                if (!IsInterestingPermission(adRule, out matchedPermissions))
                {
                    continue;
                }

                interestingRules++;
                writer.WriteLine($"[Interesting Rule {interestingRules}]");
                WriteReportField(writer, "Target Object Name", resolvedName);
                WriteReportField(writer, "Target Object DN", targetDn);
                WriteReportField(writer, "Source Principal", adRule.IdentityReference.Value);
                WriteReportField(writer, "Access Type", adRule.AccessControlType.ToString());
                WriteReportField(writer, "Matched Permissions", matchedPermissions);
                WriteReportField(writer, "AD Rights", adRule.ActiveDirectoryRights.ToString());
                WriteReportField(writer, "Object Type", FormatGuidValue(adRule.ObjectType));
                WriteReportField(writer, "Inherited Object Type", FormatGuidValue(adRule.InheritedObjectType));
                writer.WriteLine(new string('-', 92));
                writer.WriteLine();
                WriteInterestingRuleConsole(
                    interestingRules,
                    adRule.IdentityReference.Value,
                    resolvedName,
                    targetDn,
                    matchedPermissions,
                    adRule.AccessControlType.ToString());
            }

            if (interestingRules == 0)
            {
                writer.WriteLine("No interesting permissions found on this target object.");
                writer.WriteLine();
            }

            writer.WriteLine(new string('=', 92));
            writer.WriteLine($"Interesting permissions summary: {interestingRules} matching rule(s) found.");
            WriteProgressCompleted(totalRules);
        }

        WriteVerbose("Target-object permissions analysis completed.");
        return true;
    }

    private static bool TryResolveDirectoryObject(
        string domainPath,
        string targetName,
        out string objectPath,
        out string distinguishedName,
        out string resolvedName,
        out string samAccountName,
        out string sidValue)
    {
        using (DirectoryEntry rootEntry = new DirectoryEntry(domainPath))
        using (DirectorySearcher searcher = new DirectorySearcher(rootEntry))
        {
            string escaped = EscapeLdapFilterValue(targetName);
            searcher.SearchScope = SearchScope.Subtree;
            searcher.Filter = $"(|(sAMAccountName={escaped})(cn={escaped})(name={escaped})(distinguishedName={escaped}))";
            searcher.PropertiesToLoad.Add("distinguishedName");
            searcher.PropertiesToLoad.Add("name");
            searcher.PropertiesToLoad.Add("sAMAccountName");
            searcher.PropertiesToLoad.Add("objectSid");

            WriteVerbose($"Resolving target object '{targetName}'...");
            SearchResult result = searcher.FindOne();
            if (result == null)
            {
                objectPath = string.Empty;
                distinguishedName = string.Empty;
                resolvedName = string.Empty;
                samAccountName = string.Empty;
                sidValue = string.Empty;
                return false;
            }

            objectPath = result.Path;
            distinguishedName = GetSearchResultProperty(result, "distinguishedName");
            resolvedName = GetSearchResultProperty(result, "name");
            samAccountName = GetSearchResultProperty(result, "sAMAccountName");
            sidValue = GetSearchResultSid(result);

            WriteVerbose($"Resolved target object: {resolvedName} ({distinguishedName})");
            return true;
        }
    }

    private static bool TryGetUserAccessRules(string domainPath, string userName, out AuthorizationRuleCollection rules)
    {
        using (DirectoryEntry rootEntry = new DirectoryEntry(domainPath))
        using (DirectorySearcher searcher = new DirectorySearcher(rootEntry))
        {
            WriteVerbose($"Connecting to domain: {domainPath}");
            object nativeObject = rootEntry.NativeObject;
            WriteVerbose("Domain connection established.");

            searcher.SearchScope = SearchScope.Subtree;
            searcher.Filter = $"(&(objectClass=user)(sAMAccountName={EscapeLdapFilterValue(userName)}))";
            WriteVerbose($"Searching for user '{userName}'...");

            SearchResult result = searcher.FindOne();
            if (result == null)
            {
                WriteVerbose($"User '{userName}' not found in domain.");
                rules = null;
                return false;
            }

            using (DirectoryEntry userEntry = result.GetDirectoryEntry())
            {
                WriteVerbose("User located. Reading security descriptor...");
                ActiveDirectorySecurity security = userEntry.ObjectSecurity;
                rules = security.GetAccessRules(true, true, typeof(NTAccount));
                WriteVerbose($"Retrieved {rules.Count} access rule(s).");
                return true;
            }
        }
    }

    private static bool RuleMatchesPrincipal(
        ActiveDirectoryAccessRule rule,
        string inputName,
        string resolvedName,
        string samAccountName,
        string sidValue)
    {
        string identity = rule.IdentityReference.Value;
        string identityLower = identity.ToLowerInvariant();

        if (!string.IsNullOrEmpty(sidValue) && identity.Equals(sidValue, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return MatchesIdentityName(identityLower, inputName)
            || MatchesIdentityName(identityLower, resolvedName)
            || MatchesIdentityName(identityLower, samAccountName);
    }

    private static bool MatchesIdentityName(string identityLower, string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        string normalized = name.Trim().ToLowerInvariant();
        return identityLower == normalized || identityLower.EndsWith("\\" + normalized, StringComparison.Ordinal);
    }

    private static string GetSearchResultProperty(SearchResult result, string propertyName)
    {
        if (!result.Properties.Contains(propertyName) || result.Properties[propertyName].Count == 0)
        {
            return string.Empty;
        }

        object value = result.Properties[propertyName][0];
        return value == null ? string.Empty : value.ToString();
    }

    private static string GetSearchResultSid(SearchResult result)
    {
        if (!result.Properties.Contains("objectSid") || result.Properties["objectSid"].Count == 0)
        {
            return string.Empty;
        }

        byte[] sidBytes = result.Properties["objectSid"][0] as byte[];
        if (sidBytes == null || sidBytes.Length == 0)
        {
            return string.Empty;
        }

        return new SecurityIdentifier(sidBytes, 0).Value;
    }

    private static bool IsInterestingPermission(ActiveDirectoryAccessRule rule, out string matchedPermissions)
    {
        ActiveDirectoryRights rights = rule.ActiveDirectoryRights;
        StringBuilder matched = new StringBuilder();

        AppendMatchIf(rights.HasFlag(ActiveDirectoryRights.GenericAll), "GenericAll", matched);
        AppendMatchIf(rights.HasFlag(ActiveDirectoryRights.GenericWrite), "GenericWrite", matched);
        AppendMatchIf(rights.HasFlag(ActiveDirectoryRights.WriteOwner), "WriteOwner", matched);
        AppendMatchIf(rights.HasFlag(ActiveDirectoryRights.WriteDacl), "WriteDACL", matched);

        bool hasSelf = rights.HasFlag(ActiveDirectoryRights.Self);
        bool hasSelfMembership = rule.ObjectType == SelfMembershipGuid;
        AppendMatchIf(hasSelf || hasSelfMembership, "Self (Self-Membership)", matched);

        bool hasExtendedRight = rights.HasFlag(ActiveDirectoryRights.ExtendedRight);
        bool hasAllExtendedRights = hasExtendedRight && rule.ObjectType == Guid.Empty;
        bool hasForceChangePassword = hasExtendedRight && rule.ObjectType == ForceChangePasswordGuid;
        AppendMatchIf(hasAllExtendedRights, "AllExtendedRights", matched);
        AppendMatchIf(hasForceChangePassword, "ForceChangePassword", matched);

        matchedPermissions = matched.ToString();
        return matchedPermissions.Length > 0;
    }

    private static void AppendMatchIf(bool condition, string label, StringBuilder matched)
    {
        if (!condition)
        {
            return;
        }

        if (matched.Length > 0)
        {
            matched.Append(", ");
        }

        matched.Append(label);
    }

    private static void WriteInterestingReportHeader(StreamWriter writer, string userName, string domainPath, int totalRules)
    {
        writer.WriteLine("INTERESTING PERMISSIONS REPORT");
        writer.WriteLine(new string('=', 92));
        writer.WriteLine($"User            : {userName}");
        writer.WriteLine($"LDAP Path       : {domainPath}");
        writer.WriteLine($"Generated       : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        writer.WriteLine($"Rules Retrieved : {totalRules}");
        writer.WriteLine("Interesting Set : GenericAll, GenericWrite, WriteOwner, WriteDACL, AllExtendedRights,");
        writer.WriteLine("                  ForceChangePassword, Self (Self-Membership)");
        writer.WriteLine(new string('-', 92));
        writer.WriteLine();
    }

    private static void WriteInterestingSourceReportHeader(
        StreamWriter writer,
        string inputName,
        string resolvedName,
        string principalDn,
        string domainPath,
        int totalObjects)
    {
        writer.WriteLine("INTERESTING PERMISSIONS REPORT (SOURCE PRINCIPAL)");
        writer.WriteLine(new string('=', 92));
        writer.WriteLine($"Input Principal   : {inputName}");
        writer.WriteLine($"Resolved Principal: {resolvedName}");
        writer.WriteLine($"Principal DN      : {principalDn}");
        writer.WriteLine($"LDAP Path         : {domainPath}");
        writer.WriteLine($"Objects Retrieved : {totalObjects}");
        writer.WriteLine("Interesting Set   : GenericAll, GenericWrite, WriteOwner, WriteDACL, AllExtendedRights,");
        writer.WriteLine("                    ForceChangePassword, Self (Self-Membership)");
        writer.WriteLine(new string('-', 92));
        writer.WriteLine();
    }

    private static void WriteInterestingTargetReportHeader(
        StreamWriter writer,
        string inputName,
        string resolvedName,
        string targetDn,
        string domainPath,
        int totalRules)
    {
        writer.WriteLine("INTERESTING PERMISSIONS REPORT (TARGET OBJECT)");
        writer.WriteLine(new string('=', 92));
        writer.WriteLine($"Input Object      : {inputName}");
        writer.WriteLine($"Resolved Object   : {resolvedName}");
        writer.WriteLine($"Target DN         : {targetDn}");
        writer.WriteLine($"LDAP Path         : {domainPath}");
        writer.WriteLine($"Rules Retrieved   : {totalRules}");
        writer.WriteLine("Interesting Set   : GenericAll, GenericWrite, WriteOwner, WriteDACL, AllExtendedRights,");
        writer.WriteLine("                    ForceChangePassword, Self (Self-Membership)");
        writer.WriteLine(new string('-', 92));
        writer.WriteLine();
    }

    private static void WriteReportHeader(StreamWriter writer, string userName, string domainPath, int totalRules)
    {
        writer.WriteLine("ACTIVE DIRECTORY ACL REPORT");
        writer.WriteLine(new string('=', 92));
        writer.WriteLine($"User            : {userName}");
        writer.WriteLine($"LDAP Path       : {domainPath}");
        writer.WriteLine($"Generated       : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        writer.WriteLine($"Rules Retrieved : {totalRules}");
        writer.WriteLine(new string('-', 92));
        writer.WriteLine();
    }

    private static void WriteRuleBlock(StreamWriter writer, int index, ActiveDirectoryAccessRule rule)
    {
        writer.WriteLine($"[Rule {index}]");
        WriteReportField(writer, "Identity", rule.IdentityReference.Value);
        WriteReportField(writer, "Access Type", rule.AccessControlType.ToString());
        WriteReportField(writer, "AD Rights", rule.ActiveDirectoryRights.ToString());
        WriteReportField(writer, "Inheritance Type", rule.InheritanceType.ToString());
        WriteReportField(writer, "Inheritance Flags", rule.InheritanceFlags.ToString());
        WriteReportField(writer, "Propagation Flags", rule.PropagationFlags.ToString());
        WriteReportField(writer, "Object Type", FormatGuidValue(rule.ObjectType));
        WriteReportField(writer, "Inherited Object Type", FormatGuidValue(rule.InheritedObjectType));
        writer.WriteLine(new string('-', 92));
        writer.WriteLine();
    }

    private static void WriteReportField(StreamWriter writer, string label, string value)
    {
        writer.WriteLine($"  {label.PadRight(22)}: {value}");
    }

    private static string FormatGuidValue(Guid guid)
    {
        return guid == Guid.Empty ? "N/A" : guid.ToString();
    }

    private static void WriteInterestingRuleConsole(int index, string source, string target, string targetDn, string permissions, string accessType)
    {
        ConsoleColor orig = Console.ForegroundColor;
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  [!] Interesting Rule {index}");
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.Write("      Source      : ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(source);
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.Write("      Target      : ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(target);
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.Write("      Target DN   : ");
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine(targetDn);
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.Write("      Permissions : ");
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine(permissions);
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.Write("      Access      : ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(accessType);
        Console.ForegroundColor = orig;
    }

    private static void WriteVerbose(string message)
    {
        ConsoleColor originalColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"[verbose] {message}");
        Console.ForegroundColor = originalColor;
    }

    private static void WriteProgressHeader(int totalRules)
    {
        ConsoleColor originalColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine($"Collecting and writing ACL rules... total: {totalRules}");
        Console.ForegroundColor = originalColor;
    }

    private static void WriteProgress(int processed, int total)
    {
        int percentage = total == 0 ? 100 : (processed * 100) / total;

        ConsoleColor originalColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write($"\rProgress: {processed}/{total} ({percentage}%)");
        Console.ForegroundColor = originalColor;
    }

    private static void WriteProgressCompleted(int totalRules)
    {
        ConsoleColor originalColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;

        if (totalRules == 0)
        {
            Console.WriteLine("Progress: 0/0 (100%)");
        }
        else
        {
            Console.WriteLine();
        }

        Console.WriteLine("ACL collection completed.");
        Console.ForegroundColor = originalColor;
    }

    private static string ReadRequiredInput()
    {
        string value = Console.ReadLine();
        if (value == null)
        {
            throw new InvalidOperationException("Input stream is not available.");
        }

        value = value.Trim();
        if (value.Length == 0)
        {
            throw new ArgumentException("Input cannot be empty.");
        }

        return value;
    }

    private static string BuildLdapDomainPath(string domainName)
    {
        string[] components = domainName.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
        if (components.Length == 0)
        {
            throw new ArgumentException("Domain must contain at least one component.");
        }

        StringBuilder builder = new StringBuilder("LDAP://");
        for (int i = 0; i < components.Length; i++)
        {
            string component = components[i].Trim();
            if (component.Length == 0)
            {
                throw new ArgumentException("Domain contains an empty component.");
            }

            if (i > 0)
            {
                builder.Append(',');
            }

            builder.Append("DC=");
            builder.Append(component);
        }

        return builder.ToString();
    }

    private static string EscapeLdapFilterValue(string value)
    {
        StringBuilder sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            switch (c)
            {
                case '\\':
                    sb.Append("\\5c");
                    break;
                case '*':
                    sb.Append("\\2a");
                    break;
                case '(':
                    sb.Append("\\28");
                    break;
                case ')':
                    sb.Append("\\29");
                    break;
                case '\0':
                    sb.Append("\\00");
                    break;
                default:
                    sb.Append(c);
                    break;
            }
        }

        return sb.ToString();
    }

    private static string MakeSafeFileName(string value)
    {
        char[] invalidChars = Path.GetInvalidFileNameChars();
        StringBuilder sb = new StringBuilder(value.Length);

        foreach (char c in value)
        {
            bool isInvalid = false;
            for (int i = 0; i < invalidChars.Length; i++)
            {
                if (c == invalidChars[i])
                {
                    isInvalid = true;
                    break;
                }
            }

            sb.Append(isInvalid ? '_' : c);
        }

        string safe = sb.ToString().Trim();
        return safe.Length == 0 ? "user" : safe;
    }

    private static void TryApplyConsoleIcon()
    {
        try
        {
            string iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "icon.jpg");
            if (!File.Exists(iconPath))
            {
                return;
            }

            IntPtr consoleWindow = GetConsoleWindow();
            if (consoleWindow == IntPtr.Zero)
            {
                return;
            }

            using (Bitmap bitmap = (Bitmap)Image.FromFile(iconPath))
            {
                _iconHandle = bitmap.GetHicon();
            }

            SendMessage(consoleWindow, WmSetIcon, IconBig, _iconHandle);
            SendMessage(consoleWindow, WmSetIcon, IconSmall, _iconHandle);

            AppDomain.CurrentDomain.ProcessExit += (sender, args) =>
            {
                if (_iconHandle != IntPtr.Zero)
                {
                    DestroyIcon(_iconHandle);
                    _iconHandle = IntPtr.Zero;
                }
            };
        }
        catch
        {
            // Keep the tool functional even if icon loading fails.
        }
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);
}
