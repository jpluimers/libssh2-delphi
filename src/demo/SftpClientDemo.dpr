program SftpClientDemo;

uses
  Forms,
  MainFormUnit in 'MainFormUnit.pas' {MainForm},
  libssh2 in '..\libssh2.pas',
  libssh2_publickey in '..\libssh2_publickey.pas',
  libssh2_sftp in '..\libssh2_sftp.pas',
  uMySFTPClient in '..\comp\uMySFTPClient.pas',
  ProgressFormUnit in 'ProgressFormUnit.pas' {ProgressForm},
  SelectDirectoryUnit in 'SelectDirectoryUnit.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
