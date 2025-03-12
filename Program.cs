
using System;
using System.IO;
using System.DirectoryServices;
using System.Security.AccessControl;

class Program
{
    static void Main(string[] args)
    {
        // Prompt for domain name
        Console.Write("Enter the domain name (e.g., yourdomain.com): ");
        string domainName = Console.ReadLine();

        // Convert domain name to LDAP path
        string[] domainComponents = domainName.Split('.');
        string domainPath = "LDAP://";
        foreach (string component in domainComponents)
        {
            domainPath += $"DC={component},";
        }
        domainPath = domainPath.TrimEnd(',');

        // Prompt for username
        Console.Write("Enter the  Target  username: ");
        string userName = Console.ReadLine();

        try
        {
            // Use DirectorySearcher to find the user
            using (DirectoryEntry entry = new DirectoryEntry(domainPath))
            using (DirectorySearcher searcher = new DirectorySearcher(entry))
            {
                searcher.Filter = $"(&(objectClass=user)(sAMAccountName={userName}))";
                SearchResult result = searcher.FindOne();

                if (result != null)
                {
                    DirectoryEntry userEntry = result.GetDirectoryEntry();
                    ActiveDirectorySecurity userSecurity = userEntry.ObjectSecurity;

                    AuthorizationRuleCollection rules = userSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

                    // Prepare the output file
                    string fileName = $"{userName}.txt";
                    using (StreamWriter writer = new StreamWriter(fileName))
                    {
                        writer.WriteLine($"Detailed ACL for user {userName}:");
                        foreach (ActiveDirectoryAccessRule rule in rules)
                        {
                            writer.WriteLine($"Identity: {rule.IdentityReference.Value}");
                            writer.WriteLine($"Access Control Type: {rule.AccessControlType}");
                            writer.WriteLine($"Active Directory Rights: {rule.ActiveDirectoryRights}");
                            writer.WriteLine($"Inheritance Type: {rule.InheritanceType}");
                            writer.WriteLine($"Inherited Object Type: {rule.InheritedObjectType}");
                            writer.WriteLine($"Object Type: {rule.ObjectType}");
                            writer.WriteLine($"Propagation Flags: {rule.PropagationFlags}");
                            writer.WriteLine($"Inheritance Flags: {rule.InheritanceFlags}");
                            writer.WriteLine(new string('-', 40));
                        }
                    }

                    Console.WriteLine($"\nOutput saved to {fileName}");
                }
                else
                {
                    Console.WriteLine("User not found.");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
            Console.WriteLine($"Stack Trace: {ex.StackTrace}");
        }
    }
}
