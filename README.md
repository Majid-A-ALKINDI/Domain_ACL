Active Directory ACL Exporter

This is a simple C# console application that retrieves detailed Access Control List (ACL) information for a specific Active Directory user and writes the data to a text file. 
The application prompts for the domain name and username, searches for the user in Active Directory, and then exports the ACL details.
Features

    Domain Input: Converts a given domain (e.g., yourdomain.com) into an LDAP path.
    User Search: Locates a user in Active Directory using the sAMAccountName attribute.
    ACL Extraction: Retrieves and displays the user's access rules including:
        Identity
        Access Control Type (Allow/Deny)
        Active Directory Rights
        Inheritance Type and Flags
        Object and Inherited Object Type
        Propagation Flags
    File Output: Saves the extracted ACL information to a text file named after the user (e.g., username.txt).

Prerequisites

    .NET Framework (Ensure you have a compatible version installed)
    Appropriate permissions to query Active Directory

Usage
Clone the Repository:

    git clone https://github.com/Majid-A-ALKINDI/Domain_ACL.git
    cd Domain_ACL

Build the Application:

You can build the application using Visual Studio or via the command line. If using the command line, navigate to the project directory and run:

    msbuild Domain_ACL.csproj

Run the Application:

    Execute the compiled executable. The application will prompt you for the domain name and the target username.

    Domain_ACL.exe

Example Input:

    Enter the domain name (e.g., yourdomain.com): yourdomain.com
    Enter the Target username: UserX

Check Output:

    Once completed, the application will create a file named UserX.txt containing the detailed ACL information for the user.
