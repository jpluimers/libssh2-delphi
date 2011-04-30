{ **
  *  Copyright (c) 2010, Zeljko Marjanovic <savethem4ever@gmail.com>
  *  This code is licensed under MPL 1.1
  *  For details, see http://www.mozilla.org/MPL/MPL-1.1.html
  * }

unit uMySFTPClient;

interface

uses
  Windows, Classes, SysUtils, WinSock, libssh2, libssh2_sftp;

const
  AF_INET6 = 32;
  SFTPCLIENT_VERSION = '0.5';

type
  TSFTPItemType = (sitUnknown, sitDirectory, sitFile, sitSymbolicLink, sitSymbolicLinkDir,
    sitBlockDev, sitCharDev, sitFIFO, sitSocket);
  TIPVersion = (IPv4 = AF_INET, IPv6 = AF_INET6);
  TAuthMode = (amTryAll, amPassword, amPublicKey, amKeyboardInteractive, amPublicKeyViaAgent);
  TAuthModes = set of TAuthMode;
  TFingerprintState = (fsNew, fsChanged);
  TConnectHashAction = (chaCancel, chaIgnore, chaSave);
  TFingerprintEvent = procedure(ASender: TObject; const AState: TFingerprintState;
    var AAction: TConnectHashAction) of object;
  TKeybInteractiveEvent = procedure(ASender: TObject; var Password: String) of object;
  TTransferProgress = procedure(ASender: TObject; const AFileName: WideString;
    ATransfered, ATotal: UInt64) of object;
  TContinueEvent = procedure(ASender: TObject; var ACountinue: Boolean) of object;

  EWorkThreadException = class(Exception);
  ESSH2Exception = class(Exception);

  PAddrInfo = ^addrinfo;
    addrinfo = record
    ai_flags: Integer; // AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST
    ai_family: Integer; // PF_xxx
    ai_socktype: Integer; // SOCK_xxx
    ai_protocol: Integer; // 0 or IPPROTO_xxx for IPv4 and IPv6
    ai_addrlen: ULONG; // Length of ai_addr
    ai_canonname: PAnsiChar; // Canonical name for nodename
    ai_addr: PSockAddr; // Binary address
    ai_next: PAddrInfo; // Next structure in linked list
  end;

  TStructStat = struct_stat;
  PStructStat = ^TStructStat;

  TWorkThread = class(TThread)
  private
    FInterval: Cardinal;
    FNEvent: TNotifyEvent;
    FSender: TObject;
    FCanceled: Boolean;
    FEvent: THandle;
    FInEvent: THandle;
    FSyncExecute: Boolean;
    FEnabled: Boolean;
    FData: Pointer;
  protected
    procedure Execute; override;
    procedure Trigger;
  public
    constructor Create(const CreateSuspended: Boolean);
    destructor Destroy; override;
    procedure Terminate; overload;
    procedure Start;
    procedure Stop;
    property Interval: Cardinal Read FInterval Write FInterval;
    property Event: TNotifyEvent Read FNEvent Write FNEvent;
    property ThreadSender: TObject Read FSender Write FSender;
    property Data: Pointer read FData write FData;
    property SyncExecute: Boolean read FSyncExecute write FSyncExecute;
  end;

  TSFTPStatData = class(TCollectionItem)
  private
    FFileSize: UInt64;
    FUid: UInt;
    FGid: UInt;
    FPerms: Cardinal;
    FAtime: TDateTime;
    FMtime: TDateTime;
  protected
  published
    property FileSize: UInt64 read FFileSize write FFileSize;
    property UID: UInt read FUid write FUid;
    property GID: UInt read FGid write FGid;
    property Permissions: Cardinal read FPerms write FPerms;
    property LastAccessTime: TDateTime read FAtime write FAtime;
    property LastModificationTime: TDateTime read FMtime write FMtime;
  end;

  TSFTPItem = class(TSFTPStatData)
  private
    FFileName: WideString;
    FLinkPath: WideString;
    FItemType: TSFTPItemType;
    FLinkSize: UInt64;
    FHidden: Boolean;
    FGIDStr: WideString;
    FUIDStr: WideString;
    function GetPermsOct: String;
    procedure SetPermsOct(const Value: String);
  protected
  published
    procedure Assign(ASource: TPersistent); override;
    property FileName: WideString read FFileName write FFileName;
    property LinkPath: WideString read FLinkPath write FLinkPath;
    property LinkSize: UInt64 read FLinkSize write FLinkSize;
    property Hidden: Boolean read FHidden write FHidden;
    property UIDStr: WideString read FUIDStr write FUIDStr;
    property GIDStr: WideString read FGIDStr write FGIDStr;
    property PermsOctal: String read GetPermsOct write SetPermsOct;
    property ItemType: TSFTPItemType read FItemType write FItemType;
  end;

  TSFTPItems = class(TCollection)
  private
    FOwner: TComponent;
    FPath: WideString;
    function GetItems(const AIndex: Integer): TSFTPItem;
    procedure SetItems(const AIndex: Integer; const Value: TSFTPItem);
  protected
    function GetOwner: TPersistent; override;
  public
    constructor Create(AOwner: TComponent);
    function Add: TSFTPItem;
    function IndexOf(const AItem: TSFTPItem): Integer;
    procedure ParseEntryBuffers(ABuffer, ALongEntry: PAnsiChar;
      const AAttributes: LIBSSH2_SFTP_ATTRIBUTES; ACodePage: Word = CP_UTF8);
    procedure SortDefault;
    property Path: WideString read FPath write FPath;
    property Items[const AIndex: Integer]: TSFTPItem read GetItems write SetItems; default;
  end;

  THashMode = (hmMD5, hmSHA1);

  IHashManager = interface
    ['{296711A3-DE46-4674-9160-382A6F7D87A0}']
    function GetFingerprint(const AHost: String; APort: Word): Pointer; overload;
    function StoreFingerprint(const AHost: String; APort: Word; const AHash: Pointer): Boolean;
    function RemoveFingerprint(const AHost: String; APort: Word; const AHash: Pointer): Boolean;
    function CompareFingerprints(const F1, F2: Pointer): Boolean;
    function GetHashMode: THashMode;
  end;

  TSSH2Client = class(TComponent)
  private
    FPrivKeyPass: String;
    FPrivKeyPath: TFileName;
    FAuthModes: TAuthModes;
    FPubKeyPath: TFileName;
    FPort: Word;
    FPassword: String;
    FHost: String;
    FUserName: String;
    FIPVersion: TIPVersion;
    FClientBanner: String;
    FConnected: Boolean;
    FCanceled: Boolean;
    FLastErrStr: String;
    FKeepAlive: Boolean;
    FSockBufLen: Integer;
    FHashMgr: IHashManager;
    FSocket: Integer;
    FSession: PLIBSSH2_SESSION;
    FOnFingerprint: TFingerprintEvent;
    FOnKeybInt: TKeybInteractiveEvent;
    FOnAuthFail: TContinueEvent;
    FOnConnect: TNotifyEvent;
    FCodePage: Word;
    FCompression: Boolean;
    function GetConnected: Boolean;
    procedure SetConnected(const Value: Boolean);
    procedure SetAuthModes(const Value: TAuthModes);
    procedure DoOnFingerprint(const AState: TFingerprintState; var AAction: TConnectHashAction);
    function GetVersion: String;
    function GetLibString: String;
  protected
    function GetSessionPtr: PLIBSSH2_SESSION;
    function GetSocketHandle: Integer;
    function CreateSocket: Integer; virtual;
    function ConnectSocket(var S: Integer): Boolean; virtual;
    procedure RaiseSSHError(const AMsg: String = ''; E: Integer = 0); virtual;
    function MyEncode(const WS: WideString): AnsiString; virtual;
    function MyDecode(const S: AnsiString): WideString; virtual;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    procedure Connect; virtual;
    procedure Disconnect; virtual;
    function GetLastSSHError(E: Integer = 0): String; virtual;
    procedure Cancel(ADisconnect: Boolean = True); virtual;
    function GetSessionMethodsStr: String;

    property Host: String read FHost write FHost;
    property Port: Word read FPort write FPort default 22;
    property IPVersion: TIPVersion read FIPVersion write FIPVersion;
    property KeepAlive: Boolean read FKeepAlive write FKeepAlive;
    property SockSndRcvBufLen: Integer read FSockBufLen write FSockBufLen;
    property AuthModes: TAuthModes read FAuthModes write SetAuthModes default[amTryAll];
    property UserName: String read FUserName write FUserName;
    property Password: String read FPassword write FPassword;
    property PublicKeyPath: TFileName read FPubKeyPath write FPubKeyPath;
    property PrivateKeyPath: TFileName read FPrivKeyPath write FPrivKeyPath;
    property PrivKeyPassPhrase: String read FPrivKeyPass write FPrivKeyPass;
    property ClientBanner: String read FClientBanner write FClientBanner;
    property HashManager: IHashManager read FHashMgr write FHashMgr;
    property Connected: Boolean read GetConnected write SetConnected;
    property LibraryVersion: String read GetLibString;
    property Compression: Boolean read FCompression write FCompression;

    property CodePage: Word read FCodePage write FCodePage default CP_UTF8;

    property OnFingerprint: TFingerprintEvent read FOnFingerprint write FOnFingerprint;
    property OnKeybdInteractive: TKeybInteractiveEvent read FOnKeybInt write FOnKeybInt;
    property OnConnected: TNotifyEvent read FOnConnect write FOnConnect;
    property OnAuthFailed: TContinueEvent read FOnAuthFail write FOnAuthFail;
    property Version: String read GetVersion;
  end;

  TSFTPClient = class(TSSH2Client)
  private
    FCurrentDir: String;
    FItems: TSFTPItems;
    FCanceled: Boolean;
    FSFtp: PLIBSSH2_SFTP;
    FLastDirChangedOK: Boolean;
    FOnTProgress: TTransferProgress;
    FOnNoStartDir: TContinueEvent;
    FReadBufLen: Cardinal;
    FWriteBufLen: Cardinal;
    procedure SetCurrentDir(const Value: String);
  protected
    procedure RaiseSSHError(const AMsg: String = ''; E: Integer = 0); override;
    function ChangeDir(const APath: WideString): Boolean;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    procedure Connect(const ARemoteDir: WideString = '.'); reintroduce;
    procedure Disconnect; override;
    function GetLastSSHError(E: Integer = 0): String; override;
    procedure Cancel(ADisconnect: Boolean = True); override;

    procedure List(const AStartPath: WideString = '');
    procedure DeleteFile(const AFileName: WideString);
    procedure DeleteDir(const ADirName: WideString);
    procedure MakeDir(const ADirName: WideString; AMode: Integer = 0; ARecurse: Boolean = False);
    procedure Get(const ASourceFileName: WideString; const ADest: TStream; AResume: Boolean);
    procedure Put(const ASource: TStream; const ADestFileName: WideString;
      AOverwrite: Boolean = False);
    procedure Rename(const AOldName, ANewName: WideString);
    procedure MakeSymLink(const AOrigin, ADest: WideString);
    function ResolveSymLink(const AOrigin: WideString; var AAtributes: LIBSSH2_SFTP_ATTRIBUTES;
      ARealPath: Boolean = False): String;
    procedure SetAttributes(const APath: WideString; AAtribs: LIBSSH2_SFTP_ATTRIBUTES);
    procedure SetPermissions(const APath: WideString; APerms: Cardinal); overload;
    procedure SetPermissions(const APath: WideString; const AOctalPerms: String); overload;
    function ExpandCurrentDirPath: WideString;

    property ReadBufferLen: Cardinal read FReadBufLen write FReadBufLen;
    property WriteBufferLen: Cardinal read FWriteBufLen write FWriteBufLen;

    property DirectoryItems: TSFTPItems read FItems;
    property CurrentDirectory: String read FCurrentDir write SetCurrentDir;

    property OnCantChangeStartDir: TContinueEvent read FOnNoStartDir write FOnNoStartDir;
    property OnTransferProgress: TTransferProgress read FOnTProgress write FOnTProgress;
  end;

  TSCPClient = class(TSSH2Client)
  private
    FCanceled: Boolean;
    FOnTProgress: TTransferProgress;
  protected
  public
    procedure Cancel(ADisconnect: Boolean = True); override;
    procedure Get(const ASourceFileName: WideString; const ADest: TStream; var AStat: TStructStat);
    procedure Put(const ASource: TStream; const ADestFileName: WideString; AFileSize: UInt64;
      ATime, MTime: TDateTime; AMode: Integer = 0);
    property OnTransferProgress: TTransferProgress read FOnTProgress write FOnTProgress;
  end;

function ToOctal(X: Cardinal; const Len: Integer = 4): String;
function FromOctal(const S: String): Cardinal;
function EncodeStr(const WS: WideString; ACodePage: Word = CP_UTF8): AnsiString;
function DecodeStr(const S: AnsiString; ACodePage: Word = CP_UTF8): WideString;

implementation

uses
  DateUtils, Forms, WideStrUtils;

var
  GSSH2Init: Integer;

function connect2(S: TSocket; name: Pointer; namelen: Integer): Integer; stdcall;
  external 'ws2_32.dll' name 'connect';

function getaddrinfo(pNodeName, pServiceName: PAnsiChar; const pHints: PAddrInfo;
  var ppResult: PAddrInfo): Integer; stdcall; external 'ws2_32.dll' name 'getaddrinfo';

procedure freeaddrinfo(ai: PAddrInfo); stdcall; external 'ws2_32.dll' name 'freeaddrinfo';

function TestBit(const ABits, AVal: Cardinal): Boolean; inline;
begin
  Result := ABits and AVal { = AVal } <> 0;
end;

procedure ProcessMsgs;
begin
  Application.ProcessMessages;
end;

function FromOctal(const S: String): Cardinal;
var
  I: Cardinal;
begin
  Result := 0;
  for I := 1 to Length(S) do
    Result := Result * 8 + Cardinal(StrToIntDef(Copy(S, I, 1), 0));
end;

function ToOctal(X: Cardinal; const Len: Integer): String;
var
  M: Integer;
begin
  if X = 0 then
  begin
    Result := '0';
    Exit;
  end;
  Result := '';
  while X <> 0 do
  begin
    M := X mod 8;
    X := X div 8;
    Result := IntToStr(M) + Result;
  end;
  if Len > 0 then
    // Result := Format('%.'+IntToStr(Len)+'d', [StrToIntDef(Result, 0)]);
    Result := Copy(Result, Length(Result) - Len + 1, Len);
end;

function EncodeStr(const WS: WideString; ACodePage: Word): AnsiString;
var
  L: Integer;
  Flags: Cardinal;
begin
  if ACodePage = CP_UTF8 then
  begin
    Result := UTF8Encode(WS);
    Exit;
  end;

  Result := '';
  Flags := 0; // WC_COMPOSITECHECK;
  L := WideCharToMultiByte(ACodePage, Flags, @WS[1], -1, nil, 0, nil, nil);
  if L > 1 then
  begin
    SetLength(Result, L - 1);
    WideCharToMultiByte(ACodePage, Flags, @WS[1], -1, @Result[1], L - 1, nil, nil)
  end;
end;

function DecodeStr(const S: AnsiString; ACodePage: Word): WideString;
var
  L: Integer;
  Flags: Cardinal;
begin
  if ACodePage = CP_UTF8 then
  begin
    Result := UTF8Decode(S);
    Exit;
  end;

  Result := '';
  Flags := MB_PRECOMPOSED;
  L := MultiByteToWideChar(ACodePage, Flags, PAnsiChar(@S[1]), -1, nil, 0);
  if L > 1 then
  begin
    SetLength(Result, L - 1);
    MultiByteToWideChar(ACodePage, Flags, PAnsiChar(@S[1]), -1, PWideChar(@Result[1]), L - 1);
  end;
end;

{ TSFTPItem }

procedure TSFTPItem.Assign(ASource: TPersistent);
var
  X: TSFTPItem;
begin
  if ASource is TSFTPItem then
  begin
    X := TSFTPItem(ASource);
    Self.FFileName := X.FFileName;
    Self.FLinkPath := X.FLinkPath;
    Self.FItemType := X.FItemType;
    Self.FLinkSize := X.FLinkSize;
    Self.FHidden := X.FHidden;
    Self.FGIDStr := X.FGIDStr;
    Self.FUIDStr := X.FUIDStr;
    Self.FPerms := X.FPerms;
    Self.FAtime := X.FAtime;
    Self.FMtime := X.FMtime;
    Self.FFileSize := X.FFileSize;
    Self.FUid := X.FUid;
    Self.FGid := X.FGid;
  end
  else
    inherited Assign(ASource);
end;

function TSFTPItem.GetPermsOct: String;
begin
  Result := ToOctal(Permissions)
end;

procedure TSFTPItem.SetPermsOct(const Value: String);
begin
  Permissions := FromOctal(Value)
end;

{ TWorkThread }

constructor TWorkThread.Create(const CreateSuspended: Boolean);
begin
  inherited Create(CreateSuspended);
  FEnabled := not CreateSuspended;
  FreeOnTerminate := False;
  FInterval := INFINITE;
  FNEvent := nil;
  FSender := nil;
  FCanceled := False;
  FSyncExecute := True;
  FEvent := CreateEvent(nil, True, False, nil);
  FInEvent := CreateEvent(nil, True, False, nil);
  if (FEvent = 0) or (FInEvent = 0) then
    raise EWorkThreadException.Create('Could not create events.');
end;

destructor TWorkThread.Destroy;
begin
  SetEvent(FEvent);
  FCanceled := True;
  CloseHandle(FEvent);
  CloseHandle(FInEvent);
  inherited;
end;

procedure TWorkThread.Execute;
begin
  try
    while not Terminated and not FCanceled and Assigned(Self.FSender) do
    begin
      if WaitForSingleObject(FInEvent, INFINITE) = WAIT_OBJECT_0 then
      begin
        if FSyncExecute then
          Synchronize(Trigger)
        else
          Trigger;
      end;
      if WaitForSingleObject(FEvent, FInterval) = WAIT_OBJECT_0 then
        Exit;
    end;
  except
  end;
end;

procedure TWorkThread.Start;
begin
  if not FEnabled then
  begin
    if Suspended then
      Resume;
    SetEvent(FInEvent);
    FEnabled := True;
  end;
end;

procedure TWorkThread.Stop;
begin
  if FEnabled then
  begin
    FEnabled := False;
    ResetEvent(FInEvent);
    SetEvent(FEvent);
  end;
end;

procedure TWorkThread.Terminate;
begin
  SetEvent(FEvent);
  SetEvent(FInEvent);
  FCanceled := True;
  inherited Terminate;
end;

procedure TWorkThread.Trigger;
begin
  if Assigned(FNEvent) and not FCanceled and not Terminated then
    FNEvent(FSender);
end;

{ TMySFTPItems }

function TSFTPItems.Add: TSFTPItem;
begin
  Result := TSFTPItem( inherited Add);
end;

constructor TSFTPItems.Create(AOwner: TComponent);
begin
  inherited Create(TSFTPItem);
  FOwner := AOwner;
end;

function TSFTPItems.GetItems(const AIndex: Integer): TSFTPItem;
begin
  Result := TSFTPItem( inherited Items[AIndex]);
end;

function TSFTPItems.GetOwner: TPersistent;
begin
  Result := FOwner;
end;

function TSFTPItems.IndexOf(const AItem: TSFTPItem): Integer;
var
  I: Integer;
begin
  Result := -1;
  for I := 0 to Count - 1 do
    if AItem = Items[I] then
    begin
      Result := I;
      Exit;
    end;
end;

procedure TSFTPItems.ParseEntryBuffers(ABuffer, ALongEntry: PAnsiChar;
  const AAttributes: LIBSSH2_SFTP_ATTRIBUTES; ACodePage: Word);

const
  UID_POS = 3;
  GID_POS = 4;

  // surf the string to extract uid/gid name values
  // this was only tested on openssh server listing
  // hence the above constants for pos,
  // dunno if this is standardized or not
  function ExtractEntryData(ALongEntry: PAnsiChar; const APosition: Integer): String; inline;
  var
    I, J, L, K: Integer;
    S: String;
    P: PAnsiChar;
  begin
    Result := '';
    if ALongEntry = nil then
      Exit;
    J := APosition - 1;
    if J < 0 then
      J := 0;
    L := Length(ALongEntry);
    S := '';
    P := ALongEntry;
    K := 0;
    for I := 0 to L - 1 do
    begin
      if (P^ in [#9, #13, #32]) and ((P + sizeof(P^))^ <> #32) then
      begin
        Inc(P);
        Inc(K);
        Dec(J);
        if J = 0 then
        begin
          Inc(ALongEntry, I + K);
          K := I;
          for J := I to L - 1 do
          begin
            if P^ in [#0, #9, #13, #32] then
            begin
              K := J;
              break;
            end;
            Inc(P);
          end;
          SetString(S, ALongEntry, K - I);
          break;
        end
      end;
      Inc(P);
      if P^ = #0 then
        break;
    end;
    Result := S;
  end;

var
  Item: TSFTPItem;
  LinkAttrs: LIBSSH2_SFTP_ATTRIBUTES;
  Client: TSFTPClient;
begin
  if (ABuffer = nil) or (ABuffer = '.') or (ABuffer = '..') then
    Exit;

  Item := Add;
  Item.FileName := DecodeStr(ABuffer, ACodePage);
  if TestBit(AAttributes.Flags, LIBSSH2_SFTP_ATTR_PERMISSIONS) then
  begin
    case AAttributes.Permissions and LIBSSH2_SFTP_S_IFMT of
      LIBSSH2_SFTP_S_IFDIR:
        Item.ItemType := sitDirectory;
      LIBSSH2_SFTP_S_IFBLK:
        Item.ItemType := sitBlockDev;
      LIBSSH2_SFTP_S_IFIFO:
        Item.ItemType := sitFIFO;
      LIBSSH2_SFTP_S_IFCHR:
        Item.ItemType := sitCharDev;
      LIBSSH2_SFTP_S_IFSOCK:
        Item.ItemType := sitSocket;
      LIBSSH2_SFTP_S_IFLNK:
        begin
          if not(Owner is TSSH2Client) then
            Exit;
          Client := TSFTPClient(Owner);
          FillChar(LinkAttrs, sizeof(LinkAttrs), 0);
          try
            Item.LinkPath := Client.ResolveSymLink(Client.CurrentDirectory + '/' + Item.FFileName,
              LinkAttrs, True);
            if TestBit(LinkAttrs.Flags, LIBSSH2_SFTP_ATTR_PERMISSIONS) and
              (LinkAttrs.Permissions and LIBSSH2_SFTP_S_IFMT = LIBSSH2_SFTP_S_IFDIR) then
              Item.ItemType := sitSymbolicLinkDir
            else
              Item.ItemType := sitSymbolicLink;
            if TestBit(LinkAttrs.Flags, LIBSSH2_SFTP_ATTR_SIZE) then
              Item.LinkSize := LinkAttrs.FileSize
            else
              Item.LinkSize := 0;

          except
            on E: ESSH2Exception do
            begin
              Item.LinkPath := '';
              Item.LinkSize := 0;
              Item.ItemType := sitSymbolicLink;
            end;
          end;
        end;
      LIBSSH2_SFTP_S_IFREG:
        Item.ItemType := sitFile;
    end;
    Item.Permissions := AAttributes.Permissions;
  end
  else
  begin
    Item.ItemType := sitUnknown;
    Item.Permissions := 0;
  end;

  if TestBit(AAttributes.Flags, LIBSSH2_SFTP_ATTR_SIZE) then
    Item.FileSize := AAttributes.FileSize
  else
    Item.FileSize := 0;

  Item.Hidden := ABuffer[0] = '.';

  if TestBit(AAttributes.Flags, LIBSSH2_SFTP_ATTR_UIDGID) then
  begin
    Item.UID := AAttributes.UID;
    Item.GID := AAttributes.GID;
    Item.UIDStr := ExtractEntryData(ALongEntry, UID_POS);
    Item.GIDStr := ExtractEntryData(ALongEntry, GID_POS);
  end
  else
  begin
    Item.UID := 0;
    Item.GID := 0;
    Item.UIDStr := '';
    Item.GIDStr := '';
  end;

  if TestBit(AAttributes.Flags, LIBSSH2_SFTP_ATTR_ACMODTIME) then
  begin
    Item.LastAccessTime := UnixToDateTime(AAttributes.ATime);
    Item.LastModificationTime := UnixToDateTime(AAttributes.MTime);
  end
  else
  begin
    Item.LastAccessTime := 0;
    Item.LastModificationTime := 0;
  end;
end;

procedure TSFTPItems.SetItems(const AIndex: Integer; const Value: TSFTPItem);
begin
  inherited Items[AIndex] := Value;
end;

function StrCmpLogicalW(psz1, psz2: PWideChar): integer; stdcall;  external 'shlwapi.dll' name 'StrCmpLogicalW';

procedure TSFTPItems.SortDefault;
var
  T: TSFTPItem;

  function MyCmpWStr(const W1, W2: WideString): Integer;
  begin
    //Result := WideCompareStr(W1, W2) //CompareStringW(LOCALE_INVARIANT, 0, PWideChar(W1), -1, PWideChar(W2), -1);
    if W1 > W2 then
      Result := 1
    else if W1 < W2 then
      Result := -1
    else
      Result := 0;
  end;

  procedure QuickSort(AItems: TSFTPItems; L, R: Integer);
  var
    I, J: Integer;
    P: TSFTPItem;
  begin
    repeat
      I := L;
      J := R;
      P := AItems[(L + R) shr 1]; // AItems[L + Trunc(Random(R - L + 1))];
      repeat
        repeat
          Inc(I);
        until not(MyCmpWStr(AItems[I - 1].FFileName, P.FFileName) < 0);
        Dec(I);
        repeat
          Dec(J);
        until not(MyCmpWStr(P.FFileName, AItems[J + 1].FFileName) < 0);
        Inc(J);

        if I > J then
          break;

        T.Assign(AItems[I]);
        AItems[I].Assign(AItems[J]);
        AItems[J].Assign(T);

        if P = AItems[I] then
          P := AItems[J]
        else if P = AItems[J] then
          P := AItems[I];

        Inc(I);
        Dec(J);
      until I > J;

      if L < J then
        QuickSort(AItems, L, J);
      L := I;
    until I >= R;
  end;

var
  Dirs, Files: TSFTPItems;
  I, K, L: Integer;
  Item, SItem: TSFTPItem;
begin
  //
  Dirs := TSFTPItems.Create(nil);
  Files := TSFTPItems.Create(nil);
  try
    for I := 0 to Count - 1 do
    begin
      Item := Items[I];
      if Item.ItemType in [sitDirectory, sitSymbolicLinkDir] then
      begin
        SItem := Dirs.Add;
        SItem.Assign(Item);
      end
      else
      begin
        SItem := Files.Add;
        SItem.Assign(Item);
      end;
    end;

    K := Dirs.Count;
    L := Files.Count;
    T := TSFTPItem.Create(nil);
    try
      if K > 1 then
        QuickSort(Dirs, 0, K - 1);
      if L > 1 then
        QuickSort(Files, 0, L - 1);
    finally
      T.Free;
    end;

    for I := 0 to K - 1 do
      Items[I].Assign(Dirs[I]);

    for I := 0 to L - 1 do
      Items[I + K].Assign(Files[I]);

  finally
    Dirs.Free;
    Files.Free;
  end;
end;

{ TSSH2Client }

procedure TSSH2Client.Cancel(ADisconnect: Boolean);
begin
  //
  FCanceled := True;
  Sleep(500);
  try
    if ADisconnect then
      Disconnect;
  except
  end;
end;

procedure TSSH2Client.Connect;
type
  PAbstractData = ^TAbstractData;

  TAbstractData = record
    SelfPtr: Pointer;
    Extra: Pointer;
  end;

  function HandleFingerprint(const AState: TFingerprintState; const F: Pointer): Boolean;
  var
    HashAction: TConnectHashAction;
  begin
    Result := False;
    HashAction := chaIgnore;
    DoOnFingerprint(AState, HashAction);
    case HashAction of
      chaIgnore:
        ;
      chaCancel:
        Result := True;
      chaSave:
        FHashMgr.StoreFingerprint(FHost, FPort, F);
    end;
  end;

  function ParseAuthList(const AList: PAnsiChar): TAuthModes;
  var
    Modes: TAuthModes;
    S: String;
  begin
    S := String(AList);
    if amTryAll in FAuthModes then
    begin
      Result := [amTryAll];
      Exit;
    end;
    Modes := [];
    if Pos('password', S) > 0 then
      Modes := Modes + [amPassword];
    if Pos('publickey', S) > 0 then
    begin
      if amPublicKeyViaAgent in FAuthModes then
        Modes := Modes + [amPublicKeyViaAgent];
      if amPublicKey in FAuthModes then
        Modes := Modes + [amPublicKey];
    end;
    if Pos('keyboard-interactive', S) > 0 then
      Modes := Modes + [amKeyboardInteractive];

    Result := FAuthModes * Modes;
    if Result = [] then
      RaiseSSHError('Server does not support requested auth mode(s)');
  end;

  function UserAuthPassword: Boolean;
  begin
    Result := libssh2_userauth_password(FSession, PAnsiChar(AnsiString(FUserName)),
      PAnsiChar(AnsiString(FPassword))) = 0;
  end;

  procedure KbdInteractiveCallback(const Name: PAnsiChar; name_len: Integer;
    const instruction: PAnsiChar; instruction_len: Integer; num_prompts: Integer;
    const prompts: PLIBSSH2_USERAUTH_KBDINT_PROMPT;
    var responses: LIBSSH2_USERAUTH_KBDINT_RESPONSE;
      abstract: Pointer); cdecl;

  var
    Pass: String;
    Data: PAbstractData;
  begin
    if num_prompts = 1 then
    begin
      // zato sto je abstract->void**
      Data := PAbstractData(Pointer(abstract)^);
      Pass := TSSH2Client(Data.SelfPtr).Password;
      if Assigned(TSSH2Client(Data.SelfPtr).FOnKeybInt) then
        TSSH2Client(Data.SelfPtr).FOnKeybInt(Data.SelfPtr, Pass);

      if (Pass <> '') and (Pos('password', LowerCase(String(prompts.Text))) > 0) then
      begin
        responses.Text := PAnsiChar(AnsiString(Pass));
        responses.Length := Length(Pass);
      end;
    end;
  end;

  function UserAuthKeyboardInteractive: Boolean;
  begin
    Result := libssh2_userauth_keyboard_interactive(FSession, PAnsiChar(AnsiString(FUserName)),
      @KbdInteractiveCallback) = 0;
  end;

  function UserAuthPKey: Boolean;
  begin
    Result := libssh2_userauth_publickey_fromfile(FSession, PAnsiChar(AnsiString(FUserName)),
      PAnsiChar(AnsiString(FPubKeyPath)), PAnsiChar(AnsiString(FPrivKeyPath)),
      PAnsiChar(AnsiString(FPrivKeyPass))) = 0;
  end;

  function UserAuthPKeyViaAgent: Boolean;
  var
    Agent: PLIBSSH2_AGENT;
    Identity, PrevIdentity: PLIBSSH2_AGENT_PUBLICKEY;
  begin
    Result := False;
    Agent := libssh2_agent_init(FSession);
    if Agent <> nil then
    begin
      try
        if libssh2_agent_connect(Agent) = 0 then
        begin
          if libssh2_agent_list_identities(Agent) = 0 then
          begin
            PrevIdentity := nil;
            while True do
            begin
              if libssh2_agent_get_identity(Agent, Identity, PrevIdentity) <> 0 then
                break;
              if libssh2_agent_userauth(Agent, PAnsiChar(AnsiString(FUserName)), Identity) = 0 then
              begin
                Result := True;
                break;
              end;
              PrevIdentity := Identity;
            end;
          end;
          libssh2_agent_disconnect(Agent);
        end;
      finally
        libssh2_agent_free(Agent);
      end;
    end;
  end;

  function UserAuthTryAll: Boolean;
  begin
    Result := UserAuthPassword or UserAuthKeyboardInteractive or UserAuthPKey or
      UserAuthPKeyViaAgent;
  end;

label auth;

var
  Sock: Integer;
  Fingerprint, StoredFingerprint: array of Byte;
  Abstract: TAbstractData;
  Aborted: Boolean;
  UserAuthList: PAnsiChar;
  AuthMode: TAuthModes;
  AuthOK: Boolean;
  B: Boolean;
begin
  if Connected then
    Exit;
  FCanceled := False;
  Sock := CreateSocket;
  if Sock = INVALID_SOCKET then
    Exit;
  if not ConnectSocket(Sock) then
    RaiseSSHError(FLastErrStr);
  FSocket := Sock;
  if FSession <> nil then
    libssh2_session_free(FSession);

  Abstract.SelfPtr := Self;
  Abstract.Extra := nil;
  FSession := libssh2_session_init_ex(nil, nil, nil, @Abstract);
  if FSession = nil then
    RaiseSSHError;

  libssh2_banner_set(FSession, PAnsiChar(MyEncode(FClientBanner)));

  if FCompression then
  begin
    if libssh2_session_method_pref(FSession, LIBSSH2_METHOD_COMP_SC, 'zlib, none') <> 0 then
      OutputDebugStringW(PWChar(WideString('Error setting comp_sc: ' + GetLastSSHError)));

    if libssh2_session_method_pref(FSession, LIBSSH2_METHOD_COMP_CS, 'zlib, none') <> 0 then
      OutputDebugStringW(PWChar(WideString('Error setting comp_cs: ' + GetLastSSHError)));
  end;

  if libssh2_session_startup(FSession, FSocket) = 0 then
  begin
    if FHashMgr <> nil then
    begin
      case FHashMgr.GetHashMode of
        hmMD5:
          begin
            SetLength(Fingerprint, MD5_DIGEST_LENGTH);
            Pointer(Fingerprint) := libssh2_hostkey_hash(FSession, LIBSSH2_HOSTKEY_HASH_MD5);
          end;
        hmSHA1:
          begin
            SetLength(Fingerprint, SHA_DIGEST_LENGTH);
            Pointer(Fingerprint) := libssh2_hostkey_hash(FSession, LIBSSH2_HOSTKEY_HASH_SHA1);
          end;
      end;
      Aborted := False;
      StoredFingerprint := FHashMgr.GetFingerprint(FHost, FPort);
      if StoredFingerprint = nil then
        Aborted := HandleFingerprint(fsNew, Fingerprint)
      else if not FHashMgr.CompareFingerprints(Fingerprint, StoredFingerprint) then
        Aborted := HandleFingerprint(fsChanged, Fingerprint);

      if Aborted then
      begin
        Disconnect;
        Exit;
      end;
    end;

    libssh2_session_set_blocking(FSession, 1);
    libssh2_keepalive_config(FSession, Integer(FKeepAlive), 10);
    UserAuthList := libssh2_userauth_list(FSession, PAnsiChar(AnsiString(FUserName)),
      Length(AnsiString(FUserName)));
    if UserAuthList = nil then
    begin
      Disconnect;
      RaiseSSHError('Could not get user auth list.');
    end;

  auth :

    AuthOK := False;
    AuthMode := ParseAuthList(UserAuthList);
    if amTryAll in AuthMode then
      AuthOK := UserAuthTryAll
    else
    begin
      if amPassword in AuthMode then
        AuthOK := UserAuthPassword;
      if not AuthOK and (amKeyboardInteractive in AuthMode) then
        AuthOK := UserAuthKeyboardInteractive;
      if not AuthOK and (amPublicKey in AuthMode) then
        AuthOK := UserAuthPKey;
      if not AuthOK and (amPublicKeyViaAgent in AuthMode) then
        AuthOK := UserAuthPKeyViaAgent;
    end;

    if not(AuthOK and (libssh2_userauth_authenticated(FSession) > 0)) then
    begin
      B := True;
      if Assigned(FOnAuthFail) then
        FOnAuthFail(Self, B);
      if not B then
      begin
        Disconnect;
        Exit;
      end
      else
        goto auth;
    end;

    FConnected := True;
    if Assigned(FOnConnect) then
      FOnConnect(Self);
  end
  else
    RaiseSSHError;
end;

function TSSH2Client.ConnectSocket(var S: Integer): Boolean;
type
  PConectData = ^TConectData;

  TConectData = record
    S: Integer;
    ConnectRes: Integer;
    LastErr: String;
    ResAddrInfo: PAddrInfo;
    HaveRes: Boolean;
  end;

  procedure TryConnect(ASender: TObject);
  var
    PData: PConectData;
    P: PAddrInfo;
  begin
    //
    PData := PConectData(TWorkThread(ASender).Data);
    P := PData.ResAddrInfo;
    while P <> nil do
    begin
      PData.ConnectRes := connect2(PData.S, P^.ai_addr, P^.ai_addrlen);
      PData.LastErr := SysErrorMessage(WSAGetLastError);
      if PData.ConnectRes <> -1 then
        break;
      P := P^.ai_next;
    end;
    if PData.ConnectRes = -1 then
      WSACleanup;
    PData.HaveRes := True;
  end;

var
  Worker: TWorkThread;
  Data: TConectData;
  Hints: addrinfo;
  E: TMethod;
begin
  Result := False;
  if S <> INVALID_SOCKET then
  begin
    Data.HaveRes := False;
    Data.ConnectRes := -1;
    Data.S := S;

    FillChar(Hints, sizeof(Hints), 0);
    Hints.ai_family := AF_UNSPEC; // both ipv4 and ipv6
    Hints.ai_socktype := SOCK_STREAM;
    Hints.ai_protocol := IPPROTO_TCP;

    if getaddrinfo(PAnsiChar(AnsiString(FHost)), PAnsiChar(AnsiString(IntToStr(FPort))), @Hints,
      Data.ResAddrInfo) <> 0 then
      RaiseSSHError(SysErrorMessage(WSAGetLastError));

    Worker := TWorkThread.Create(True);
    try
      Worker.SyncExecute := False;
      Worker.ThreadSender := Worker;
      E.Code := @TryConnect;
      E.Data := Worker;
      Worker.Event := TNotifyEvent(E);
      Worker.Data := @Data;
      Worker.Start;
      while not(Data.HaveRes or FCanceled or Application.Terminated) do
      begin
        ProcessMsgs;
        Sleep(1);
      end;
      Worker.Stop;
      FLastErrStr := Data.LastErr;
      if not Worker.Terminated then
      begin
        Worker.Terminate;
        if FCanceled then
          TerminateThread(Worker.Handle, 0); // hiyoooo!!
      end;
    finally
      Worker.Free;
      freeaddrinfo(Data.ResAddrInfo);
    end;
    if not FCanceled then
      Result := Data.ConnectRes <> -1;
  end;
end;

constructor TSSH2Client.Create(AOwner: TComponent);
begin
  inherited;
  FHost := '';
  FPort := 22;
  FUserName := '';
  FPassword := '';
  FIPVersion := IPv4;
  FAuthModes := [amTryAll];
  FClientBanner := LIBSSH2_SSH_BANNER;
  FConnected := False;
  FCanceled := False;
  FKeepAlive := False;
  FSockBufLen := 8 * 1024;
  FSocket := INVALID_SOCKET;
  FCodePage := CP_UTF8;
  FCompression := False;
  if InterlockedIncrement(GSSH2Init) = 1 then
    if libssh2_init(0) <> 0 then
      RaiseSSHError('Error initializing libssh2.');
end;

function TSSH2Client.CreateSocket: Integer;
var
  WSData: TWSAData;
begin
  Result := INVALID_SOCKET;
  if WSAStartup(MakeWord(2, 2), WSData) <> 0 then
  begin
    RaiseSSHError('Invalid winsock version!');
    Exit;
  end;
  Result := socket(Ord(FIPVersion), SOCK_STREAM, IPPROTO_TCP);
  if Result = INVALID_SOCKET then
  begin
    RaiseSSHError(SysErrorMessage(WSAGetLastError));
    Exit;
  end;

  setsockopt(Result, SOL_SOCKET, SO_SNDBUF, @FSockBufLen, sizeof(FSockBufLen));
  setsockopt(Result, SOL_SOCKET, SO_RCVBUF, @FSockBufLen, sizeof(FSockBufLen));
  setsockopt(Result, SOL_SOCKET, SO_KEEPALIVE, @FKeepAlive, sizeof(FKeepAlive));
end;

destructor TSSH2Client.Destroy;
begin
  if Connected then
    Disconnect;
  if InterlockedDecrement(GSSH2Init) < 1 then
    libssh2_exit;
  inherited;
end;

procedure TSSH2Client.Disconnect;
begin
  try
    if FSession <> nil then
    begin
      libssh2_session_disconnect(FSession,
        PAnsiChar(AnsiString(FClientBanner + ': ' + GetVersion + ' going to shutdown. Bye.')));
      libssh2_session_free(FSession);
    end;
  finally
    closesocket(FSocket);
    FSocket := INVALID_SOCKET;
    FSession := nil;
    WSACleanup;
    FConnected := False;
  end;
end;

procedure TSSH2Client.DoOnFingerprint(const AState: TFingerprintState;
  var AAction: TConnectHashAction);
begin
  if Assigned(FOnFingerprint) then
    FOnFingerprint(Self, AState, AAction);
end;

function TSSH2Client.GetConnected: Boolean;
{ var
  Buf: Pointer; }
begin
  Result := False;
  if (FSession = nil) or { (FSFtp = nil) or } (FSocket = INVALID_SOCKET) then
    Exit;
  { if WinSock.send(FSocket, Buf, 0, 0) = SOCKET_ERROR then
    Exit; }
  Result := FConnected;
end;

function TSSH2Client.GetLastSSHError(E: Integer): String;
var
  I: Integer;
  P: PAnsiChar;
begin
  if E = 0 then
    Result := SysErrorMessage(WSAGetLastError)
  else
    Result := 'No error';
  I := 0;
  P := PAnsiChar(AnsiString(Result));
  if FSession <> nil then
    libssh2_session_last_error(FSession, P, I, 0);
  Result := String(P);
end;

function TSSH2Client.GetLibString: String;
begin
  Result := String(libssh2_version(0));
end;

function TSSH2Client.GetSessionMethodsStr: String;
begin
  Result := '';
  if FSession <> nil then
    Result := Format('KEX: %s, CRYPT: %s, MAC: %s, COMP: %s, LANG: %s',
      [libssh2_session_methods(FSession, LIBSSH2_METHOD_KEX), libssh2_session_methods(FSession,
        LIBSSH2_METHOD_CRYPT_CS), libssh2_session_methods(FSession, LIBSSH2_METHOD_MAC_CS),
      libssh2_session_methods(FSession, LIBSSH2_METHOD_COMP_CS), libssh2_session_methods(FSession,
        LIBSSH2_METHOD_LANG_CS)]);
end;

function TSSH2Client.GetSessionPtr: PLIBSSH2_SESSION;
begin
  Result := FSession;
end;

function TSSH2Client.GetSocketHandle: Integer;
begin
  Result := FSocket;
end;

function TSSH2Client.GetVersion: String;
begin
  Result := ClassName + ' v' + SFTPCLIENT_VERSION;
end;

function TSSH2Client.MyDecode(const S: AnsiString): WideString;
begin
  Result := DecodeStr(S, FCodePage);
end;

function TSSH2Client.MyEncode(const WS: WideString): AnsiString;
begin
  Result := EncodeStr(WS, FCodePage);
end;

procedure TSSH2Client.RaiseSSHError(const AMsg: String; E: Integer);
begin
  //
  if AMsg <> '' then
    raise ESSH2Exception.Create(AMsg)
  else
    raise ESSH2Exception.Create(GetLastSSHError(E));
end;

procedure TSSH2Client.SetAuthModes(const Value: TAuthModes);
begin
  if FAuthModes <> Value then
  begin
    if Value = [] then
      Exit;
    if amTryAll in Value then
    begin
      FAuthModes := [amTryAll];
      Exit;
    end;
    FAuthModes := Value;
  end;
end;

procedure TSSH2Client.SetConnected(const Value: Boolean);
begin
  if FConnected <> Value then
  begin
    FConnected := Value;
    if Value then
      Connect
    else
      Disconnect;
  end;
end;

{ TSFTPClient }

procedure TSFTPClient.Cancel(ADisconnect: Boolean);
begin
  //
  FCanceled := True;
  inherited;
end;

function TSFTPClient.ChangeDir(const APath: WideString): Boolean;
var
  DirHandle: PLIBSSH2_SFTP_HANDLE;
begin
  Result := False;
  if FSFtp <> nil then
  begin
    DirHandle := libssh2_sftp_opendir(FSFtp, PAnsiChar(MyEncode(APath)));
    if DirHandle <> nil then
    begin
      libssh2_sftp_closedir(DirHandle);
      Result := True;
    end;
  end;
  FLastDirChangedOK := Result;
end;

procedure TSFTPClient.Connect(const ARemoteDir: WideString);
var
  Dir: WideString;
  B: Boolean;
begin
  inherited Connect;
  if not Connected then
    Exit;
  FSFtp := libssh2_sftp_init(GetSessionPtr);
  if FSFtp = nil then
  begin
    Disconnect;
    RaiseSSHError;
  end;

  Dir := ExpandCurrentDirPath;
  if Dir = '' then
  begin
    B := True;
    if Assigned(FOnNoStartDir) then
      FOnNoStartDir(Self, B);
    if not B then
    begin
      Disconnect;
      Exit;
    end;
  end;

  if ARemoteDir <> '.' then
    if ARemoteDir <> Dir then
    begin
      if ChangeDir(ARemoteDir) then
        Dir := ARemoteDir
      else
      begin
        B := True;
        if Assigned(FOnNoStartDir) then
          FOnNoStartDir(Self, B);
        if not B then
        begin
          Disconnect;
          Exit;
        end;
      end;
    end;
  CurrentDirectory := Dir;
end;

constructor TSFTPClient.Create(AOwner: TComponent);
begin
  inherited;
  FCurrentDir := '.';
  FItems := TSFTPItems.Create(Self);
  FItems.Path := '';
  FLastDirChangedOK := False;
  FReadBufLen := 16 * 1024;
  FWriteBufLen := 8 * 1024 - 1;
end;

procedure TSFTPClient.DeleteDir(const ADirName: WideString);
begin
  FCanceled := False;
  if libssh2_sftp_rmdir(FSFtp, PAnsiChar(MyEncode(ADirName))) <> 0 then
    RaiseSSHError;
end;

procedure TSFTPClient.DeleteFile(const AFileName: WideString);
begin
  FCanceled := False;
  if libssh2_sftp_unlink(FSFtp, PAnsiChar(MyEncode(AFileName))) <> 0 then
    RaiseSSHError;
end;

destructor TSFTPClient.Destroy;
begin
  FItems.Free;
  if Connected then
    Disconnect;
  inherited;
end;

procedure TSFTPClient.Disconnect;
begin
  try
    if FSFtp <> nil then
      libssh2_sftp_shutdown(FSFtp);
    inherited;
  finally
    FSFtp := nil;
  end;
end;

function TSFTPClient.ExpandCurrentDirPath: WideString;
const
  BUF_LEN = 4 * 1024;
var
  DirHandle: PLIBSSH2_SFTP_HANDLE;
  Buf: PAnsiChar;
begin
  Result := '';

  DirHandle := libssh2_sftp_opendir(FSFtp, '.');
  if DirHandle <> nil then
  begin
    GetMem(Buf, BUF_LEN);
    try
      libssh2_sftp_realpath(FSFtp, nil, Buf, BUF_LEN);
      libssh2_sftp_close(DirHandle);
      Result := MyDecode(Buf);
    finally
      FreeMem(Buf);
    end;
  end
  else
    RaiseSSHError;
end;

procedure TSFTPClient.Get(const ASourceFileName: WideString; const ADest: TStream;
  AResume: Boolean);
var
  Attribs: LIBSSH2_SFTP_ATTRIBUTES;
  Transfered, Total: UInt64;
  FHandle: PLIBSSH2_SFTP_HANDLE;
  Buf: PAnsiChar;
  R, N: Integer;
begin
  //
  FCanceled := False;
  if libssh2_sftp_stat(FSFtp, PAnsiChar(MyEncode(ASourceFileName)), Attribs) = 0 then
  begin
    if not TestBit(Attribs.Flags, LIBSSH2_SFTP_ATTR_SIZE) then
      OutputDebugStringW(PWChar('TSFTPClient::Get >> No size attrib:' + ASourceFileName));

    FHandle := libssh2_sftp_open(FSFtp, PAnsiChar(MyEncode(ASourceFileName)), LIBSSH2_FXF_READ, 0);
    if FHandle = nil then
      RaiseSSHError;

    if AResume then
    begin
      Total := Attribs.FileSize - ADest.Position;
      libssh2_sftp_seek64(FHandle, ADest.Position);
    end
    else
      Total := Attribs.FileSize;

    Transfered := 0;
    GetMem(Buf, FReadBufLen);
    try
      repeat
        R := libssh2_sftp_read(FHandle, Buf, FReadBufLen);
        if R > 0 then
        begin
          N := ADest.Write(Buf^, R);
          if N > 0 then
          begin
            Inc(Transfered, N);
            if Assigned(FOnTProgress) then
              FOnTProgress(Self, ASourceFileName, Transfered, Total);
          end;
        end
        else if R < 0 then
          RaiseSSHError;
      until (R = 0) or FCanceled;
    finally
      FreeMem(Buf);
      libssh2_sftp_close(FHandle);
    end;
  end
  else
    RaiseSSHError;
end;

function TSFTPClient.GetLastSSHError(E: Integer): String;
var
  S: String;
  C: Integer;
begin
  S := inherited GetLastSSHError(E);
  if FSFtp <> nil then
  begin
    S := 'SFTP: ';
    if E = 0 then
      C := libssh2_sftp_last_error(FSFtp)
    else
      C := E;
    case C of
      LIBSSH2_FX_OK:
        S := S + 'No error';
      LIBSSH2_FX_EOF:
        S := S + 'End of file';
      LIBSSH2_FX_NO_SUCH_FILE:
        S := S + 'No such file';
      LIBSSH2_FX_PERMISSION_DENIED:
        S := S + 'Permission denied';
      LIBSSH2_FX_FAILURE:
        S := S + 'Failure';
      LIBSSH2_FX_BAD_MESSAGE:
        S := S + 'Bad messagge';
      LIBSSH2_FX_NO_CONNECTION:
        S := S + 'No connection';
      LIBSSH2_FX_CONNECTION_LOST:
        S := S + 'Connection lost';
      LIBSSH2_FX_OP_UNSUPPORTED:
        S := S + 'Operation unsupported';
      LIBSSH2_FX_INVALID_HANDLE:
        S := S + 'Invalid handle';
      LIBSSH2_FX_NO_SUCH_PATH:
        S := S + 'No such path';
      LIBSSH2_FX_FILE_ALREADY_EXISTS:
        S := S + 'File exists';
      LIBSSH2_FX_WRITE_PROTECT:
        S := S + 'Write protect';
      LIBSSH2_FX_NO_MEDIA:
        S := S + 'No media';
      LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM:
        S := S + 'No space on filesystem';
      LIBSSH2_FX_QUOTA_EXCEEDED:
        S := S + 'Quota exceeded';
      LIBSSH2_FX_UNKNOWN_PRINCIPAL:
        S := S + 'Unknown principal';
      LIBSSH2_FX_LOCK_CONFlICT:
        S := S + 'Lock conflict';
      LIBSSH2_FX_DIR_NOT_EMPTY:
        S := S + 'Directory not empty';
      LIBSSH2_FX_NOT_A_DIRECTORY:
        S := S + 'Not a directory';
      LIBSSH2_FX_INVALID_FILENAME:
        S := S + 'Invalid filename';
      LIBSSH2_FX_LINK_LOOP:
        S := S + 'Link loop'
      else
        S := S + 'Unknown error'
    end;
  end;
  Result := S;
end;

procedure TSFTPClient.List(const AStartPath: WideString);
const
  BUF_LEN = 4 * 1024;
var
  EntryBuffer: array [0 .. BUF_LEN - 1] of AnsiChar;
  LongEntry: array [0 .. BUF_LEN - 1] of AnsiChar;
  Attribs: LIBSSH2_SFTP_ATTRIBUTES;
  R: Integer;
  DirHandle: PLIBSSH2_SFTP_HANDLE;
begin
  if not Connected then
    Exit;
  FCanceled := False;
  if AStartPath <> '' then
    if AStartPath <> FCurrentDir then
      if not ChangeDir(AStartPath) then
        RaiseSSHError('Could not change to dir: ' + AStartPath + ' :: ' + GetLastSSHError)
      else
        FCurrentDir := AStartPath;

  DirHandle := libssh2_sftp_opendir(FSFtp, PAnsiChar(MyEncode(CurrentDirectory)));
  if DirHandle = nil then
    RaiseSSHError('Could not open dir: ' + GetLastSSHError);

  FItems.Clear;
  FItems.BeginUpdate;
  try
    repeat
      R := libssh2_sftp_readdir_ex(DirHandle, EntryBuffer, BUF_LEN, LongEntry, BUF_LEN, @Attribs);
      if (R <= 0) or FCanceled then
        break;
      FItems.ParseEntryBuffers(EntryBuffer, LongEntry, Attribs, FCodePage);
    until not True;
  finally
    FItems.EndUpdate;
    libssh2_sftp_closedir(DirHandle);
    FItems.Path := FCurrentDir;
  end;
end;

procedure TSFTPClient.MakeDir(const ADirName: WideString; AMode: Integer; ARecurse: Boolean);
var
  Dir: WideString;
  Mode: Integer;
begin
  FCanceled := False;
  if ADirName = '' then
    Exit;

  if ARecurse then
  begin
    Dir := ExtractFileDir(WideStringReplace(ADirName, '/', '\', [rfReplaceAll, rfIgnoreCase]));
    if (Dir <> '') then
    begin
      Dir := WideStringReplace(Dir, '/', '\', [rfReplaceAll, rfIgnoreCase]);
      if not ChangeDir(Dir) then
        MakeDir(Dir, AMode, ARecurse);
    end;
  end;

  if AMode <> 0 then
    Mode := AMode
  else
    // mkdir with standard perms 0755
    Mode := LIBSSH2_SFTP_S_IRWXU or LIBSSH2_SFTP_S_IRGRP or LIBSSH2_SFTP_S_IXGRP or
      LIBSSH2_SFTP_S_IROTH or LIBSSH2_SFTP_S_IXOTH;

  if libssh2_sftp_mkdir(FSFtp, PAnsiChar(MyEncode(ADirName)), Mode) <> 0 then
    RaiseSSHError;
end;

procedure TSFTPClient.MakeSymLink(const AOrigin, ADest: WideString);
begin
  FCanceled := False;
  if libssh2_sftp_symlink(FSFtp, PAnsiChar(MyEncode(ADest)), PAnsiChar(MyEncode(AOrigin))) <> 0 then
    RaiseSSHError;
end;

procedure TSFTPClient.Put(const ASource: TStream; const ADestFileName: WideString;
  AOverwrite: Boolean);
var
  R, N, K: Integer;
  Mode: Integer;
  FHandle: PLIBSSH2_SFTP_HANDLE;
  Buf, StartBuf: PAnsiChar;
  Transfered, Total: UInt64;
begin
  FCanceled := False;
  Mode := LIBSSH2_FXF_WRITE or LIBSSH2_FXF_CREAT;
  if AOverwrite then
    Mode := Mode or LIBSSH2_FXF_TRUNC
  else
    Mode := Mode or LIBSSH2_FXF_EXCL; // ensure call fails if file exists

  FHandle := libssh2_sftp_open(FSFtp, PAnsiChar(MyEncode(ADestFileName)), Mode,
    LIBSSH2_SFTP_S_IRUSR or LIBSSH2_SFTP_S_IWUSR or LIBSSH2_SFTP_S_IRGRP or
      LIBSSH2_SFTP_S_IROTH);
  if FHandle = nil then
    RaiseSSHError;

  GetMem(Buf, FWriteBufLen);
  StartBuf := Buf;
  Transfered := 0;
  Total := ASource.Size - ASource.Position;
  try
    repeat
      N := ASource.Read(Buf^, FWriteBufLen);
      if N > 0 then
      begin
        K := N;
        repeat
          R := libssh2_sftp_write(FHandle, Buf, K);
          if R < 0 then
            RaiseSSHError;
          Inc(Transfered, R);
          Inc(Buf, R);
          Dec(K, R);
          if Assigned(FOnTProgress) then
            FOnTProgress(Self, ADestFileName, Transfered, Total);
        until (K <= 0) or FCanceled;
        Buf := StartBuf;
      end;
    until (N <= 0) or FCanceled;
  finally
    FreeMem(Buf);
    libssh2_sftp_close(FHandle);
  end;
end;

procedure TSFTPClient.RaiseSSHError(const AMsg: String; E: Integer);
begin
  inherited;
  //
end;

procedure TSFTPClient.Rename(const AOldName, ANewName: WideString);
begin
  FCanceled := False;
  if libssh2_sftp_rename(FSFtp, PAnsiChar(MyEncode(AOldName)), PAnsiChar(MyEncode(ANewName)))
    <> 0 then
    RaiseSSHError;
end;

function TSFTPClient.ResolveSymLink(const AOrigin: WideString;
  var AAtributes: LIBSSH2_SFTP_ATTRIBUTES; ARealPath: Boolean): String;
const
  BUF_LEN = 4 * 1024;
var
  Target: array [0 .. BUF_LEN - 1] of AnsiChar;
  R: Integer;
begin
  FCanceled := False;
  Result := '';
  if not ARealPath then
    R := libssh2_sftp_readlink(FSFtp, PAnsiChar(MyEncode(AOrigin)), PAnsiChar(@Target), BUF_LEN)
  else
    R := libssh2_sftp_realpath(FSFtp, PAnsiChar(MyEncode(AOrigin)), PAnsiChar(@Target), BUF_LEN);

  if R > 0 then
  begin
    Result := MyDecode(Target);
    libssh2_sftp_stat(FSFtp, PAnsiChar(@Target), AAtributes);
  end
  else
    RaiseSSHError;
end;

procedure TSFTPClient.SetAttributes(const APath: WideString; AAtribs: LIBSSH2_SFTP_ATTRIBUTES);
begin
  FCanceled := False;
  if libssh2_sftp_setstat(FSFtp, PAnsiChar(MyEncode(APath)), AAtribs) <> 0 then
    RaiseSSHError;
end;

procedure TSFTPClient.SetCurrentDir(const Value: String);
begin
  if FCurrentDir <> Value then
    if ChangeDir(Value) then
    begin
      FCurrentDir := Value;
      FItems.Path := Value;
    end;
end;

procedure TSFTPClient.SetPermissions(const APath: WideString; const AOctalPerms: String);
begin
  SetPermissions(APath, FromOctal(AOctalPerms));
end;

procedure TSFTPClient.SetPermissions(const APath: WideString; APerms: Cardinal);
var
  Attribs: LIBSSH2_SFTP_ATTRIBUTES;
begin
  FillChar(Attribs, sizeof(Attribs), 0);
  Attribs.Flags := LIBSSH2_SFTP_ATTR_PERMISSIONS;
  Attribs.Permissions := APerms;
  SetAttributes(APath, Attribs);
end;

{ TSCPClient }

procedure TSCPClient.Cancel(ADisconnect: Boolean);
begin
  FCanceled := True;
  inherited;
end;

procedure TSCPClient.Get(const ASourceFileName: WideString; const ADest: TStream;
  var AStat: TStructStat);
const
  BUF_LEN = 8 * 1024 - 1;
var
  Channel: PLIBSSH2_CHANNEL;
  N, R, K: Integer;
  Buf: array [0 .. BUF_LEN - 1] of AnsiChar;
begin
  //
  FCanceled := False;
  Channel := libssh2_scp_recv(GetSessionPtr, PAnsiChar(MyEncode(ASourceFileName)), AStat);
  if Channel = nil then
    RaiseSSHError;
  try
    N := 0;
    K := BUF_LEN;
    while (N < AStat.st_size) and not FCanceled do
    begin
      if AStat.st_size - N < K then
        K := AStat.st_size - N;

      R := libssh2_channel_read(Channel, Buf, K);
      if K = R then
      begin
        ADest.Write(Buf, K);
        if Assigned(FOnTProgress) then
          FOnTProgress(Self, ASourceFileName, N, AStat.st_size);
      end
      else
        RaiseSSHError;
      Inc(N, R);
    end;
  finally
    libssh2_channel_free(Channel);
  end;
end;

procedure TSCPClient.Put(const ASource: TStream; const ADestFileName: WideString;
  AFileSize: UInt64; ATime, MTime: TDateTime; AMode: Integer);
const
  BUF_LEN = 8 * 1024 - 1;
var
  Channel: PLIBSSH2_CHANNEL;
  Mode: Integer;
  Buf, StartBuf: PAnsiChar;
  N, K, R: Integer;
  Transfered: UInt64;
begin
  //
  FCanceled := False;
  if AMode <> 0 then
    Mode := AMode
  else
    Mode := LIBSSH2_SFTP_S_IRUSR or LIBSSH2_SFTP_S_IWUSR or LIBSSH2_SFTP_S_IRGRP or
      LIBSSH2_SFTP_S_IROTH;
  Channel := libssh2_scp_send64(GetSessionPtr, PAnsiChar(MyEncode(ADestFileName)), Mode, AFileSize,
    DateTimeToUnix(ATime), DateTimeToUnix(MTime));
  if Channel = nil then
    RaiseSSHError;
  GetMem(Buf, BUF_LEN);
  StartBuf := Buf;
  Transfered := 0;
  try
    repeat
      N := ASource.Read(Buf^, BUF_LEN);
      if N > 0 then
      begin
        K := N;
        repeat
          R := libssh2_channel_write(Channel, Buf, K);
          if R < 0 then
            RaiseSSHError;
          Inc(Transfered, R);
          Inc(Buf, R);
          Dec(K, R);
          if Assigned(FOnTProgress) then
            FOnTProgress(Self, ADestFileName, Transfered, AFileSize);
        until (K <= 0) or FCanceled;
        Buf := StartBuf;
      end;
    until (N <= 0) or FCanceled;
    libssh2_channel_send_eof(Channel);
    libssh2_channel_wait_eof(Channel);
    libssh2_channel_wait_closed(Channel);
  finally
    FreeMem(Buf);
    libssh2_channel_free(Channel);
  end;
end;

initialization

GSSH2Init := 0;

finalization

end.
