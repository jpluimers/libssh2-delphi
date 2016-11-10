unit ProgressFormUnit;

interface

uses
  System.Classes,
  Vcl.Controls,
  Vcl.Forms,
  Vcl.StdCtrls,
  Vcl.ComCtrls,
  uMySFTPClient;

type
  TProgressForm = class(TForm)
    ProgressBar: TProgressBar;
    CancelButton: TButton;
    ProgressLabel: TLabel;
    procedure CancelButtonClick(Sender: TObject);
  public
    procedure DoProgress(const AProgressMessage: WideString; const APosition,
        AMaximum: UInt64);
    procedure ShowWith(const ACaption: string);
  end;

implementation

{$R *.dfm}

procedure TProgressForm.CancelButtonClick(Sender: TObject);
begin
  ModalResult := mrCancel;
end;

procedure TProgressForm.DoProgress(const AProgressMessage: WideString; const
    APosition, AMaximum: UInt64);
begin
  ProgressBar.Max := AMaximum;
  ProgressBar.Position := APosition;
  ProgressLabel.Caption := AProgressMessage;
  Update;
end;

procedure TProgressForm.ShowWith(const ACaption: string);
begin
  Caption := ACaption;
  Show();
end;

end.
