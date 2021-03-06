@{

# ���� ������ �������� ��� ��������� ������, ��������� � ���� ����������.
# RootModule = ''

# ����� ������ ������� ������.
ModuleVersion = '1.0.2'

# ���������� ������������� ������� ������
GUID = 'ff6bd1d3-0f2f-4fca-a6ab-2d77024c6a22'

# ����� ������� ������
Author = 'SAGSa'

# ��������, ��������� ������ ������, ��� ��� ���������
CompanyName = '����������'

# ��������� �� ��������� ������ �� ������
Copyright = '(c) 2018 SAGSa'

# �������� ������� ������� ������
Description = '
This module helps to create custom windows event forwarding Logs
'

# ����������� ����� ������ ����������� Windows PowerShell, ����������� ��� ������ ������� ������
PowerShellVersion = '2.0'

# ��� ���� Windows PowerShell, ������������ ��� ������ ������� ������
# PowerShellHostName = ''

# ����������� ����� ������ ���� Windows PowerShell, ����������� ��� ������ ������� ������
# PowerShellHostVersion = ''

# ����������� ����� ������ Microsoft .NET Framework, ����������� ��� ������� ������
# DotNetFrameworkVersion = ''

# ����������� ����� ������ ����� CLR (������������ ����� ����������), ����������� ��� ������ ������� ������
# CLRVersion = ''

# ����������� ���������� (���, X86, AMD64), ����������� ��� ����� ������
# ProcessorArchitecture = ''

# ������, ������� ���������� ������������� � ���������� ����� ����� ��������������� ������� ������
# RequiredModules = @()

# ������, ������� ������ ���� ��������� ����� ��������������� ������� ������
# RequiredAssemblies = @()

# ����� �������� (PS1), ������� ����������� � ����� ���������� ������� ����� �������� ������� ������.
# ScriptsToProcess = @()

# ����� ���� (.ps1xml), ������� ����������� ��� ������� ������� ������
# TypesToProcess = @()

# ����� ������� (PS1XML-�����), ������� ����������� ��� ������� ������� ������
#FormatsToProcess = ''

# ������ ��� ������� � �������� ��������� ������� ������, ���������� � ��������� RootModule/ModuleToProcess
NestedModules = 'WecEventlog.psm1'

# ���������� ��� �������� �� ������� ������
#CmdletsToExport = '*'

# ���������� ��� �������� �� ������� ������
VariablesToExport = '*'

# ���������� ��� �������� �� ������� ������
#AliasesToExport = '*'

# ������� DSC ��� �������� �� ����� ������
# DscResourcesToExport = @()

# ������ ���� �������, �������� � ����� ������� ������
# ModuleList = @()

# ������ ���� ������, �������� � ����� ������� ������
# FileList = @()

# ������ ������ ��� �������� � ������, ��������� � ��������� RootModule/ModuleToProcess. �� ����� ����� ��������� ���-������� PSData � ��������������� ����������� ������, ������� ������������ � PowerShell.
PrivateData = @{

    PSData = @{

        # ����, ���������� � ����� ������. ��� �������� � ������������ ������ � ������-����������.
        Tags = @('EventCollector', 'EventSubscription', 'EventLog', 'WEC', 'ForwardedEvents')

        # URL-����� �������� ��� ����� ������.
        LicenseUri = ''

        # URL-����� �������� ���-����� ��� ����� �������.
        ProjectUri = 'https://github.com/SAGSA/WecEventlog'

        # URL-����� ������, ������� ������������ ���� ������.
        # IconUri = ''

        # ������� � ������� ����� ������
        ReleaseNotes = @' 
## 1.0.2
*  First release
'@

    } # ����� ���-������� PSData

} # ����� ���-������� PrivateData

# ��� URI ��� HelpInfo ������� ������
# HelpInfoURI = ''

# ������� �� ��������� ��� ������, ���������������� �� ����� ������. �������������� ������� �� ��������� � ������� ������� Import-Module -Prefix.
# DefaultCommandPrefix = ''

}