unit MainFormUnit;

interface

uses
  System.Classes,
  Vcl.Controls,
  Vcl.Forms,
  uMySFTPClient,
  Vcl.StdCtrls,
  Vcl.ComCtrls,
  Vcl.ExtCtrls,
  ProgressFormUnit;

type
  TMainForm = class(TForm)
    btnGet: TButton;
    btnPut: TButton;
    RemoteFilesListView: TListView;
    lblCurDir: TLabel;
    edHost: TLabeledEdit;
    edPort: TLabeledEdit;
    rbIP4: TRadioButton;
    rbIP6: TRadioButton;
    GroupBox1: TGroupBox;
    cbTryAll: TCheckBox;
    cbPass: TCheckBox;
    cbKeybInt: TCheckBox;
    cbPKey: TCheckBox;
    cbPKeyAgent: TCheckBox;
    btnConnect: TButton;
    btnDisconnect: TButton;
    edUser: TLabeledEdit;
    edPass: TLabeledEdit;
    cbKeepAlive: TCheckBox;
    btnDelete: TButton;
    btnRename: TButton;
    btnMkSymlink: TButton;
    btnResSymlink: TButton;
    btnMkDir: TButton;
    StatusBar1: TStatusBar;
    edPkey: TLabeledEdit;
    edPrivkey: TLabeledEdit;
    edPrivkpass: TLabeledEdit;
    btnSelPkey: TButton;
    btnSelPrivkey: TButton;
    btnSetPerms: TButton;
    procedure FormCreate(Sender: TObject);
    procedure btnConnectClick(Sender: TObject);
    procedure RemoteFilesListViewDblClick(Sender: TObject);
    procedure btnDisconnectClick(Sender: TObject);
    procedure btnMkDirClick(Sender: TObject);
    procedure btnResSymlinkClick(Sender: TObject);
    procedure btnMkSymlinkClick(Sender: TObject);
    procedure btnRenameClick(Sender: TObject);
    procedure btnDeleteClick(Sender: TObject);
    procedure btnPutClick(Sender: TObject);
    procedure btnGetClick(Sender: TObject);
    procedure btnSelPkeyClick(Sender: TObject);
    procedure btnSelPrivkeyClick(Sender: TObject);
    procedure cbTryAllClick(Sender: TObject);
  strict private
    SFTPClient: TSFTPClient;
    FProgressForm: TProgressForm;
    procedure FillList;
    function GetProgressForm: TProgressForm;
    procedure OnProgress(const ASender: TObject; const AFileName: WideString; const ATransfered, ATotal: UInt64);
    procedure OnCantChangeStartDir(const ASender: TObject; var Continue: Boolean);
    procedure OnAuthFailed(const ASender: TObject; var Continue: Boolean);
    function OnKeybdInteractive(const ASender: TObject; var Password: string): Boolean;
    procedure ReflectSftpClientConnectedState();
    procedure SFTPClientList(const AStartPath: WideString = '');
    property ProgressForm: TProgressForm read GetProgressForm;
  end;

var
  MainForm: TMainForm;

implementation

uses
  System.SysUtils,
  System.WideStrUtils,
  Vcl.Dialogs,
  libssh2_sftp,
  SelectDirectoryUnit;

{$R *.dfm}

procedure TMainForm.btnConnectClick(Sender: TObject);
var
  Mode: TAuthModes;
begin
  SFTPClient.UserName := edUser.Text;
  SFTPClient.Password := edPass.Text;
  SFTPClient.Host := edHost.Text;
  SFTPClient.Port := StrToIntDef(edPort.Text, 22);
  SFTPClient.KeepAlive := cbKeepAlive.Checked;
  if rbIP4.Checked then
    SFTPClient.IPVersion := IPv4
  else
    SFTPClient.IPVersion := IPv6;

  if cbTryAll.Checked then
    SFTPClient.AuthModes := [amTryAll]
  else
  begin
    Mode := [];
    if cbPass.Checked then
      Mode := Mode + [amPassword];
    if cbKeybInt.Checked then
      Mode := Mode + [amKeyboardInteractive];
    if cbPKey.Checked then
      Mode := Mode + [amPublicKey];
    if cbPKeyAgent.Checked then
      Mode := Mode + [amPublicKeyViaAgent];
    if Mode = [] then
    begin
      ShowMessage('You must select at least one auth mode.');
      Exit;
    end;
    SFTPClient.AuthModes := Mode;
  end;
  SFTPClient.PublicKeyPath := edPkey.Text;
  SFTPClient.PrivateKeyPath := edPrivkey.Text;
  SFTPClient.PrivKeyPassPhrase := edPrivkpass.Text;
  try
    SFTPClient.Connect;
    ReflectSftpClientConnectedState();
  except
    on E: ESSH2Exception do
      ShowMessage(E.Message);
  end;
end;

procedure TMainForm.btnDisconnectClick(Sender: TObject);
begin
  SFTPClient.Disconnect;
  ReflectSftpClientConnectedState();
end;

procedure TMainForm.btnGetClick(Sender: TObject);
var
  Dir: string;
  FS: TFileStream;
  I: Integer;
begin
  if RemoteFilesListView.SelCount = 1 then
    if RemoteFilesListView.Selected.Caption <> '..' then
    begin
      if SelectDirectory('Select dir where to save the file', '', Dir) then
      begin
        I := RemoteFilesListView.Selected.Index;
        if RemoteFilesListView.Items[0].Caption = '..' then
          Dec(I);

        // process "file" items only, on the otherside
        // if the item is symlink, then we could resolve it and
        // follow the path
        if SFTPClient.DirectoryItems[I].ItemType <> sitFile then
        begin
          ShowMessage('Select file first.');
          Exit;
        end;
        // the code below is put in a tworkerthread in the original program
        // this is just a demo, so :P
        FS := TFileStream.Create(IncludeTrailingPathDelimiter(Dir) + SFTPClient.DirectoryItems[I].FileName, fmCreate);
        try
          ProgressForm.ShowWith('Getting file...');
          try
            SFTPClient.Get(SFTPClient.CurrentDirectory + '/' + SFTPClient.DirectoryItems[I].FileName, FS, False)
          except on E: ESSH2Exception do
            ShowMessage(E.Message);
          end;
        finally
          ProgressForm.Close;
          FS.Free;
        end;
      end;
    end;
end;

procedure TMainForm.btnPutClick(Sender: TObject);
var
  FS: TFileStream;
begin
  with TOpenDialog.Create(Self) do
  begin
    Title := 'Select file';
    Filter := '*.*';
    if Execute(Handle) then
    begin
      // the code below is put in a tworkerthread in the original program
      // this is just a demo, so :P
      FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
      try
        ProgressForm.ShowWith('Putting file...');
        try
          SFTPClient.Put(FS, SFTPClient.CurrentDirectory + '/' + ExtractFileName(FileName));
          SFTPClientList();
        except
          on E: ESSH2Exception do
            ShowMessage(E.Message);
        end;
      finally
        ProgressForm.Close;
        FS.Free;
      end;
    end;
    Free;
  end;
end;

procedure TMainForm.btnDeleteClick(Sender: TObject);
var
  I: Integer;
begin
  if RemoteFilesListView.SelCount = 1 then
    if RemoteFilesListView.Selected.Caption <> '..' then
    begin
      if MessageDlg('Are you sure?', mtWarning, mbYesNo, 0) = mrNo then
        Exit;
      I := RemoteFilesListView.Selected.Index;
      if RemoteFilesListView.Items[0].Caption = '..' then
        Dec(I);
      try
        if SFTPClient.DirectoryItems[I].ItemType = sitDirectory then
          SFTPClient.DeleteDir(SFTPClient.CurrentDirectory + '/' + SFTPClient.DirectoryItems[I].FileName)
        else
          SFTPClient.DeleteFile(SFTPClient.CurrentDirectory + '/' + SFTPClient.DirectoryItems[I].FileName);

        SFTPClientList();
      except
        on E: ESSH2Exception do
          ShowMessage(E.Message);
      end;
    end;
end;

procedure TMainForm.btnRenameClick(Sender: TObject);
var
  I: Integer;
  NewName: string;
begin
  if RemoteFilesListView.SelCount = 1 then
    if RemoteFilesListView.Selected.Caption <> '..' then
    begin
      I := RemoteFilesListView.Selected.Index;
      if RemoteFilesListView.Items[0].Caption = '..' then
        Dec(I);
      NewName := SFTPClient.DirectoryItems[I].FileName;
      if InputQuery('Rename', 'Enter new name', NewName) then
        try
          SFTPClient.Rename(SFTPClient.DirectoryItems[I].FileName, SFTPClient.CurrentDirectory + '/' + NewName);
          SFTPClientList();
        except
          on E: ESSH2Exception do
            ShowMessage(E.Message);
        end;
    end;
end;

procedure TMainForm.btnMkSymlinkClick(Sender: TObject);
var
  ATarget, AName: string;
begin
  ATarget := '';
  if RemoteFilesListView.SelCount = 1 then
    if RemoteFilesListView.Selected.Caption <> '..' then
      ATarget := SFTPClient.CurrentDirectory + '/' + RemoteFilesListView.Selected.Caption;
  if InputQuery('Link target', 'Enter link target', ATarget) then
    if InputQuery('Link name', 'Enter link name', AName) then
      try
        SFTPClient.MakeSymLink(SFTPClient.CurrentDirectory + '/' + AName, ATarget);
        SFTPClientList();
      except
        on E: ESSH2Exception do
          ShowMessage(E.Message);
      end;
end;

procedure TMainForm.btnResSymlinkClick(Sender: TObject);
var
  A: LIBSSH2_SFTP_ATTRIBUTES;
  I: Integer;
  S, S1: WideString;
begin
  if SFTPClient.Connected and (RemoteFilesListView.SelCount = 1) then
  begin
    try
      if RemoteFilesListView.Selected.Caption <> '..' then
      begin
        I := RemoteFilesListView.Selected.Index;
        if RemoteFilesListView.Items[0].Caption = '..' then
          Dec(I);

        if SFTPClient.DirectoryItems[I].ItemType in [sitSymbolicLink, sitSymbolicLinkDir] then
        begin
          S := SFTPClient.ResolveSymLink(SFTPClient.CurrentDirectory + '/' + RemoteFilesListView.Selected.Caption, A);
          S1 := SFTPClient.ResolveSymLink(SFTPClient.CurrentDirectory + '/' + RemoteFilesListView.Selected.Caption, A,
            True);
          ShowMessage('Links to: ' + S + #13#10 + 'Realpath: ' + S1);
        end;
      end;
    except
      on E: ESSH2Exception do
        ShowMessage(E.Message);
    end;
  end;
end;

procedure TMainForm.btnSelPkeyClick(Sender: TObject);
begin
  with TOpenDialog.Create(Self) do
  begin
    Title := 'Select public key file';
    Filter := '*.*';
    if Execute(Handle) then
      edPkey.Text := FileName;
    Free;
  end;
end;

procedure TMainForm.btnSelPrivkeyClick(Sender: TObject);
begin
  with TOpenDialog.Create(Self) do
  begin
    Title := 'Select private key file';
    Filter := '*.*';
    if Execute(Handle) then
      edPrivkey.Text := FileName;
    Free;
  end;
end;

procedure TMainForm.cbTryAllClick(Sender: TObject);
begin
  cbPass.Enabled := not cbTryAll.Checked;
  cbKeybInt.Enabled := not cbTryAll.Checked;
  cbPKey.Enabled := not cbTryAll.Checked;
  cbPKeyAgent.Enabled := not cbTryAll.Checked;
end;

procedure TMainForm.btnMkDirClick(Sender: TObject);
var
  Dir: string;
begin
  if InputQuery('Create directory', 'Directory name', Dir) then
  begin
    SFTPClient.MakeDir(SFTPClient.CurrentDirectory + '/' + Dir);
    SFTPClientList();
  end;
end;

procedure TMainForm.FillList;
  function ItemTypeToStr(AType: TSFTPItemType): string;
  begin
    Result := '';
    case AType of
      sitUnknown:
        Result := 'unknown';
      sitDirectory:
        Result := '<DIR>';
      sitFile:
        Result := 'file';
      sitSymbolicLink:
        Result := 'symlink';
      sitSymbolicLinkDir:
        Result := '<LNK>';
      sitBlockDev:
        Result := 'block';
      sitCharDev:
        Result := 'char';
      sitFIFO:
        Result := 'fifo';
      sitSocket:
        Result := 'socket';
    end;
  end;

var
  I: Integer;
  Item: TListItem;
  SFTPItem: TSFTPItem;
begin
  lblCurDir.Caption := SFTPClient.CurrentDirectory;
  RemoteFilesListView.Clear;
  RemoteFilesListView.Items.BeginUpdate;
  SFTPClient.DirectoryItems.SortDefault;
  if SFTPClient.CurrentDirectory <> '/' then
    RemoteFilesListView.AddItem('..', nil);
  for I := 0 to SFTPClient.DirectoryItems.Count - 1 do
  begin
    SFTPItem := SFTPClient.DirectoryItems[I];
    Item := RemoteFilesListView.Items.Add;
    Item.Caption := SFTPItem.FileName;
    Item.SubItems.Add(ItemTypeToStr(SFTPItem.ItemType));
    Item.SubItems.Add(IntToStr(SFTPItem.FileSize));
    Item.SubItems.Add(SFTPItem.PermsOctal);
    Item.SubItems.Add(SFTPItem.UIDStr + '-' + SFTPItem.GIDStr);
    Item.SubItems.Add(DateTimeToStr(SFTPItem.LastModificationTime));
  end;
  RemoteFilesListView.Items.EndUpdate;
end;

procedure TMainForm.FormCreate(Sender: TObject);
begin
  SFTPClient := TSFTPClient.Create(Self);
  SFTPClient.OnTransferProgress := OnProgress;
  SFTPClient.OnAuthFailed := OnAuthFailed;
  SFTPClient.OnCantChangeStartDir := OnCantChangeStartDir;
  SFTPClient.OnKeybdInteractive := OnKeybdInteractive;
  StatusBar1.Panels[1].Text := 'libssh2 ver: ' + SFTPClient.LibraryVersion;
end;

function TMainForm.GetProgressForm: TProgressForm;
begin
  if not Assigned(FProgressForm) then
    FProgressForm := TProgressForm.Create(Self);
  Result := FProgressForm;
end;

procedure TMainForm.ReflectSftpClientConnectedState;
var
  IsConnected: Boolean;
begin
  IsConnected := SFTPClient.Connected;

  if IsConnected then
  begin
    StatusBar1.Panels[0].Text := SFTPClient.GetSessionMethodsStr;
    SFTPClientList();
  end
  else
  begin
    RemoteFilesListView.Clear;
    StatusBar1.Panels[0].Text := '';
    lblCurDir.Caption := '::';
  end;

  btnConnect.Enabled := not IsConnected;
  btnDisconnect.Enabled := IsConnected;
  btnGet.Enabled := IsConnected;
  btnPut.Enabled := IsConnected;
  btnDelete.Enabled := IsConnected;
  btnRename.Enabled := IsConnected;
  btnMkSymlink.Enabled := IsConnected;
  btnResSymlink.Enabled := IsConnected;
  btnMkDir.Enabled := IsConnected;
  btnSetPerms.Enabled := IsConnected;
end;

procedure TMainForm.RemoteFilesListViewDblClick(Sender: TObject);
var
  W: WideString;
  Item: TListItem;
  A: LIBSSH2_SFTP_ATTRIBUTES;
  I: Integer;
begin
  if RemoteFilesListView.SelCount = 1 then
  begin
    try
      Item := RemoteFilesListView.Selected;
      if Item.Caption = '..' then
      begin
        W := ExtractFileDir(WideStringReplace(SFTPClient.CurrentDirectory, '/', PathDelim, [rfReplaceAll,
            rfIgnoreCase]));
        if W = '' then
          W := '/'
        else
          W := WideStringReplace(W, PathDelim, '/', [rfReplaceAll, rfIgnoreCase]);
        SFTPClientList(W);
        Exit;
      end;

      I := Item.Index;
      if (I <> 0) and (RemoteFilesListView.Items[0].Caption = '..') then
        Dec(I);
      if SFTPClient.DirectoryItems[I].ItemType in [sitDirectory, sitSymbolicLinkDir] then
      begin
        if SFTPClient.DirectoryItems[I].ItemType = sitSymbolicLinkDir then
        begin
          W := SFTPClient.ResolveSymLink(SFTPClient.CurrentDirectory + '/' + Item.Caption, A, True);
          if W = '' then
            W := '/';
          SFTPClientList(W);
        end
        else
        begin
          W := SFTPClient.CurrentDirectory;
          if W = '/' then
            W := '';
          SFTPClientList(W + '/' + Item.Caption);
        end;
      end;

    except
      on E: ESSH2Exception do
        ShowMessage(E.Message);
    end;
  end;
end;

procedure TMainForm.OnAuthFailed(const ASender: TObject; var Continue: Boolean);
begin
  Continue := MessageDlg('Auth failed. Try again?', mtConfirmation, mbYesNo, 0) = mrYes;
end;

procedure TMainForm.OnCantChangeStartDir(const ASender: TObject; var Continue: Boolean);
begin
  Continue := MessageDlg('Could not change to start dir. Continue?', mtConfirmation, mbYesNo, 0) = mrYes;
end;

function TMainForm.OnKeybdInteractive(const ASender: TObject; var Password: string): Boolean;
begin
  // The #8 forces GetPasswordChar inside InputQuery to ensure it's a password prompt.
  Result := InputQuery('Enter password for kybdinteractive', #8'Password', Password);
end;

procedure TMainForm.OnProgress(const ASender: TObject; const AFileName: WideString; const ATransfered, ATotal: UInt64);
begin
  if Assigned(FProgressForm) then
  begin
    ProgressForm.DoProgress(AFileName, ATransfered, ATotal);
    Application.ProcessMessages();
    if ProgressForm.ModalResult = mrCancel then
      SFTPClient.Cancel(False);
    if ATransfered >= ATotal then
      ProgressForm.ModalResult := mrOk;
  end;
end;

procedure TMainForm.SFTPClientList(const AStartPath: WideString = '');
begin
  SFTPClient.List(AStartPath);
  FillList();
end;

end.
