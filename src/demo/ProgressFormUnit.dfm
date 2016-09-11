object ProgressForm: TProgressForm
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Processing'
  ClientHeight = 80
  ClientWidth = 327
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poOwnerFormCenter
  PixelsPerInch = 96
  TextHeight = 13
  object ProgressLabel: TLabel
    Left = 8
    Top = 8
    Width = 8
    Height = 13
    Caption = '::'
  end
  object ProgressBar: TProgressBar
    Left = 8
    Top = 24
    Width = 311
    Height = 17
    TabOrder = 0
  end
  object CancelButton: TButton
    Left = 244
    Top = 47
    Width = 75
    Height = 23
    Cancel = True
    Caption = '&Cancel'
    Default = True
    TabOrder = 1
    OnClick = CancelButtonClick
  end
end
