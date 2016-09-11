unit SelectDirectoryUnit;

interface

uses
  Vcl.Controls,
{$WARN UNIT_PLATFORM OFF}
  Vcl.FileCtrl
{$WARN UNIT_PLATFORM ON}
  ;

function SelectDirectory(const Caption: string; const Root: WideString;
  var Directory: string; Options: TSelectDirExtOpts = [sdNewUI]; Parent: TWinControl = nil): Boolean; overload;

implementation

uses
  System.SysUtils,
  Vcl.Dialogs;

function SelectDirectory(const Caption: string; const Root: WideString;
  var Directory: string; Options: TSelectDirExtOpts = [sdNewUI]; Parent: TWinControl = nil): Boolean; overload;
var
{$WARN SYMBOL_PLATFORM OFF}
  FileOpenDialog: TFileOpenDialog;
{$WARN SYMBOL_PLATFORM ON}
begin
  if Win32MajorVersion >= 6 then
  begin
{$WARN SYMBOL_PLATFORM OFF}
    FileOpenDialog := TFileOpenDialog.Create(nil);
{$WARN SYMBOL_PLATFORM ON}
    try
{$WARN SYMBOL_PLATFORM OFF}
      FileOpenDialog.Title := Caption;
      FileOpenDialog.Options := [fdoPickFolders, fdoPathMustExist, fdoForceFileSystem]; // YMMV
      FileOpenDialog.OkButtonLabel := 'Select';
      FileOpenDialog.DefaultFolder := Directory;
      FileOpenDialog.FileName := Directory;
{$WARN SYMBOL_PLATFORM ON}
      Result := FileOpenDialog.Execute;
{$WARN SYMBOL_PLATFORM OFF}
      Directory := FileOpenDialog.FileName;
{$WARN SYMBOL_PLATFORM ON}
    finally
      FileOpenDialog.Free();
    end
  end
  else
    Result := Vcl.FileCtrl.SelectDirectory(Caption, Root, Directory, Options);
end;

end.
