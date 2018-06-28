unit uMainForm;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  Classes,
  SysUtils,
  Forms,
  Controls,
  StdCtrls,
  ExtCtrls,
  ComCtrls,
  Spin,
  TypInfo,
  uPascalCoinKeyTool;

type

  { TMainForm }

  TMainForm = class(TForm)
    btnStressTest: TButton;
    btnClearAESMemoLogger: TButton;
    btnClearStressTestMemoLogger: TButton;
    btnClearPrivateKeyMemoLogger: TButton;
    btnClearECIESMemoLogger: TButton;
    btnAESEncryptDecrypt: TButton;
    btnEncryptDecryptPrivateKey: TButton;
    btnECIESEncryptDecrypt: TButton;
    cmbAESEncryptionModes: TComboBox;
    cmbPrivateKeyEncryptionModes: TComboBox;
    cmbECIESEncryptionModes: TComboBox;
    edtMessageToSign: TEdit;
    edtAESPayloadPassword: TEdit;
    edtEncryptPassword: TEdit;
    edtECIESPayload: TEdit;
    edtECIESPrivateKeyPassword: TEdit;
    edtAESPayload: TEdit;
    edtPrivateKey: TEdit;
    edtECIESKey: TEdit;
    mmoAESLoggerMemo: TMemo;
    mmoStressTestLoggerMemo: TMemo;
    mmoPrivateKeyLoggerMemo: TMemo;
    btnGenerateKeyPair: TButton;
    btnClearLogger: TButton;
    cmbKeyTypes: TComboBox;
    MainPanel: TPanel;
    mmoLoggerMemo: TMemo;
    MainPageControl: TPageControl;
    mmoECIESLoggerMemo: TMemo;
    speIterationCount: TSpinEdit;
    tbsStressTest: TTabSheet;
    tbsAESEncryptDecrypt: TTabSheet;
    tbsECIESEncryptDecrypt: TTabSheet;
    tbsGenerateKeyPair: TTabSheet;
    edtPrivateKeyPassword: TEdit;
    tbsEncryptDecryptPrivateKey: TTabSheet;
    procedure btnAESEncryptDecryptClick(Sender: TObject);
    procedure btnClearAESMemoLoggerClick(Sender: TObject);
    procedure btnClearECIESMemoLoggerClick(Sender: TObject);
    procedure btnClearLoggerClick(Sender: TObject);
    procedure btnClearPrivateKeyMemoLoggerClick(Sender: TObject);
    procedure btnClearStressTestMemoLoggerClick(Sender: TObject);
    procedure btnECIESEncryptDecryptClick(Sender: TObject);
    procedure btnEncryptDecryptPrivateKeyClick(Sender: TObject);
    procedure btnStressTestClick(Sender: TObject);
    procedure cmbAESEncryptionModesChange(Sender: TObject);
    procedure cmbECIESEncryptionModesChange(Sender: TObject);
    procedure cmbPrivateKeyEncryptionModesChange(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure btnGenerateKeyPairClick(Sender: TObject);
  private
    type
    {$SCOPEDENUMS ON}
    TPrivateKeyEncryptionMode = (Encrypt, Decrypt);
    TECIESEncryptionMode = (Encrypt, Decrypt);
    TAESEncryptionMode = (Encrypt, Decrypt);
    {$SCOPEDENUMS OFF}
  public

  end;

var
  MainForm: TMainForm;

implementation

{$R *.lfm}


{ TMainForm }

procedure TMainForm.FormCreate(Sender: TObject);
var
  KeyType: TKeyType;
  PrivateKeyEncryptionMode: TPrivateKeyEncryptionMode;
  ECIESEncryptionMode: TECIESEncryptionMode;
  AESEncryptionMode: TAESEncryptionMode;
begin
  cmbKeyTypes.Clear;
  for  KeyType in TKeyType do
    cmbKeyTypes.AddItem(GetEnumName(TypeInfo(TKeyType), Ord(KeyType)), TObject(KeyType));
  cmbKeyTypes.ItemIndex := 0;

  cmbPrivateKeyEncryptionModes.Clear;
  for PrivateKeyEncryptionMode in TPrivateKeyEncryptionMode do
    cmbPrivateKeyEncryptionModes.AddItem(GetEnumName(TypeInfo(TPrivateKeyEncryptionMode), Ord(PrivateKeyEncryptionMode)), TObject(PrivateKeyEncryptionMode));
  cmbPrivateKeyEncryptionModes.ItemIndex := 0;
  cmbPrivateKeyEncryptionModesChange(Self);

  cmbECIESEncryptionModes.Clear;
  for ECIESEncryptionMode in TECIESEncryptionMode do
    cmbECIESEncryptionModes.AddItem(GetEnumName(TypeInfo(TECIESEncryptionMode), Ord(ECIESEncryptionMode)), TObject(ECIESEncryptionMode));
  cmbECIESEncryptionModes.ItemIndex := 0;
  cmbECIESEncryptionModesChange(Self);

  cmbAESEncryptionModes.Clear;
  for AESEncryptionMode in TAESEncryptionMode do
    cmbAESEncryptionModes.AddItem(GetEnumName(TypeInfo(TAESEncryptionMode), Ord(AESEncryptionMode)), TObject(AESEncryptionMode));
  cmbAESEncryptionModes.ItemIndex := 0;
  cmbAESEncryptionModesChange(Self);
end;

procedure TMainForm.btnClearLoggerClick(Sender: TObject);
begin
  mmoLoggerMemo.Clear;
end;

procedure TMainForm.btnClearECIESMemoLoggerClick(Sender: TObject);
begin
  mmoECIESLoggerMemo.Clear;
end;

procedure TMainForm.btnClearAESMemoLoggerClick(Sender: TObject);
begin
  mmoAESLoggerMemo.Clear;
end;

procedure TMainForm.btnAESEncryptDecryptClick(Sender: TObject);
var
  CurrentlySelected: TAESEncryptionMode;
  Logger: TStringList;
  Payload: string;
begin
  CurrentlySelected := TAESEncryptionMode(GetEnumValue(TypeInfo(TAESEncryptionMode), cmbAESEncryptionModes.Items[cmbAESEncryptionModes.ItemIndex]));
  case CurrentlySelected of
    TAESEncryptionMode.Encrypt:
    begin
      Payload := Trim(edtAESPayload.Text);
      if (Payload <> '') then
      begin
        Logger := TStringList.Create();
        try
          TPascalCoinKeyTool.EncryptPascalCoinAESPayload(edtAESPayloadPassword.Text, Payload, Logger);
          mmoAESLoggerMemo.Lines.AddStrings(Logger, False);
        finally
          Logger.Free;
        end;
      end;
    end;

    TAESEncryptionMode.Decrypt:
    begin
      Payload := Trim(edtAESPayload.Text);
      if (Payload <> '') then
      begin
        Logger := TStringList.Create();
        try
          TPascalCoinKeyTool.DecryptPascalCoinAESPayload(edtAESPayloadPassword.Text, Payload, Logger);
          mmoAESLoggerMemo.Lines.AddStrings(Logger, False);
        finally
          Logger.Free;
        end;
      end;
    end;
  end;
end;

procedure TMainForm.btnClearPrivateKeyMemoLoggerClick(Sender: TObject);
begin
  mmoPrivateKeyLoggerMemo.Clear;
end;

procedure TMainForm.btnClearStressTestMemoLoggerClick(Sender: TObject);
begin
  mmoStressTestLoggerMemo.Clear;
end;

procedure TMainForm.btnECIESEncryptDecryptClick(Sender: TObject);
var
  CurrentlySelected: TECIESEncryptionMode;
  SelectedKeyType: TKeyType;
  Logger: TStringList;
  PascalCoinPublicKey, EncryptedPascalCoinPrivateKey, Payload: string;
begin
  CurrentlySelected := TECIESEncryptionMode(GetEnumValue(TypeInfo(TECIESEncryptionMode), cmbECIESEncryptionModes.Items[cmbECIESEncryptionModes.ItemIndex]));
  SelectedKeyType := TKeyType(GetEnumValue(TypeInfo(TKeyType), cmbKeyTypes.Items[cmbKeyTypes.ItemIndex]));
  case CurrentlySelected of
    TECIESEncryptionMode.Encrypt:
    begin
      PascalCoinPublicKey := Trim(edtECIESKey.Text);
      Payload := Trim(edtECIESPayload.Text);
      if ((PascalCoinPublicKey <> '') and (Payload <> '')) then
      begin
        Logger := TStringList.Create();
        try
          TPascalCoinKeyTool.EncryptPascalCoinECIESPayload(SelectedKeyType, PascalCoinPublicKey, Payload, Logger);
          mmoECIESLoggerMemo.Lines.AddStrings(Logger, False);
        finally
          Logger.Free;
        end;
      end;
    end;

    TECIESEncryptionMode.Decrypt:
    begin
      EncryptedPascalCoinPrivateKey := Trim(edtECIESKey.Text);
      Payload := Trim(edtECIESPayload.Text);
      if ((EncryptedPascalCoinPrivateKey <> '') and (Payload <> '')) then
      begin
        Logger := TStringList.Create();
        try
          TPascalCoinKeyTool.DecryptPascalCoinECIESPayload(SelectedKeyType, EncryptedPascalCoinPrivateKey, edtECIESPrivateKeyPassword.Text, Payload, Logger);
          mmoECIESLoggerMemo.Lines.AddStrings(Logger, False);
        finally
          Logger.Free;
        end;
      end;
    end;
  end;
end;

procedure TMainForm.btnEncryptDecryptPrivateKeyClick(Sender: TObject);
var
  CurrentlySelected: TPrivateKeyEncryptionMode;
  SelectedKeyType: TKeyType;
  Logger: TStringList;
  PrivateKeyToEncrypt, EncryptedPascalCoinPrivateKey: string;
begin
  CurrentlySelected := TPrivateKeyEncryptionMode(GetEnumValue(TypeInfo(TPrivateKeyEncryptionMode), cmbPrivateKeyEncryptionModes.Items[cmbPrivateKeyEncryptionModes.ItemIndex]));
  case CurrentlySelected of
    TPrivateKeyEncryptionMode.Encrypt:
    begin
      SelectedKeyType := TKeyType(GetEnumValue(TypeInfo(TKeyType), cmbKeyTypes.Items[cmbKeyTypes.ItemIndex]));
      PrivateKeyToEncrypt := Trim(edtPrivateKey.Text);
      if PrivateKeyToEncrypt <> '' then
      begin
        Logger := TStringList.Create();
        try
          TPascalCoinKeyTool.EncryptPascalCoinPrivateKey(SelectedKeyType, PrivateKeyToEncrypt, edtPrivateKeyPassword.Text, Logger);
          mmoPrivateKeyLoggerMemo.Lines.AddStrings(Logger, False);
        finally
          Logger.Free;
        end;
      end;
    end;

    TPrivateKeyEncryptionMode.Decrypt:
    begin
      EncryptedPascalCoinPrivateKey := Trim(edtPrivateKey.Text);
      if EncryptedPascalCoinPrivateKey <> '' then
      begin
        Logger := TStringList.Create();
        try
          TPascalCoinKeyTool.DecryptPascalCoinPrivateKey(EncryptedPascalCoinPrivateKey, edtPrivateKeyPassword.Text, Logger);
          mmoPrivateKeyLoggerMemo.Lines.AddStrings(Logger, False);
        finally
          Logger.Free;
        end;
      end;
    end;
  end;
end;

procedure TMainForm.btnStressTestClick(Sender: TObject);
var
  SelectedKeyType: TKeyType;
  Logger: TStringList;
begin
  SelectedKeyType := TKeyType(GetEnumValue(TypeInfo(TKeyType), cmbKeyTypes.Items[cmbKeyTypes.ItemIndex]));
  Logger := TStringList.Create();
  try
    btnStressTest.Enabled := False;
    TPascalCoinKeyTool.Generate_Recreate_Sign_Verify_ECDSA_Stress_Test(SelectedKeyType, edtMessageToSign.Text, speIterationCount.Value, Logger);
    mmoStressTestLoggerMemo.Lines.AddStrings(Logger, False);
  finally
    Logger.Free;
    btnStressTest.Enabled := True;
  end;
end;

procedure TMainForm.cmbAESEncryptionModesChange(Sender: TObject);
var
  CurrentlySelected: TAESEncryptionMode;
begin
  CurrentlySelected := TAESEncryptionMode(GetEnumValue(TypeInfo(TAESEncryptionMode), cmbAESEncryptionModes.Items[cmbAESEncryptionModes.ItemIndex]));
  case CurrentlySelected of
    TAESEncryptionMode.Encrypt:
    begin
      edtAESPayloadPassword.TextHint := 'Encryption Password';
      edtAESPayload.TextHint := 'Payload To Encrypt';
      btnAESEncryptDecrypt.Caption := 'Encrypt Payload with AES';
    end;

    TAESEncryptionMode.Decrypt:
    begin
      edtAESPayloadPassword.TextHint := 'Decryption Password';
      edtAESPayload.TextHint := 'Payload To Decrypt';
      btnAESEncryptDecrypt.Caption := 'Decrypt Payload with AES';
    end;
  end;
end;

procedure TMainForm.cmbECIESEncryptionModesChange(Sender: TObject);
var
  CurrentlySelected: TECIESEncryptionMode;
begin
  CurrentlySelected := TECIESEncryptionMode(GetEnumValue(TypeInfo(TECIESEncryptionMode), cmbECIESEncryptionModes.Items[cmbECIESEncryptionModes.ItemIndex]));
  case CurrentlySelected of
    TECIESEncryptionMode.Encrypt:
    begin
      edtECIESPrivateKeyPassword.Clear;
      edtECIESPrivateKeyPassword.TextHint := '';
      edtECIESPrivateKeyPassword.Visible := False;
      edtECIESKey.TextHint := 'PascalCoin Public Key (In Base58) To Use For Encryption';
      edtECIESPayload.TextHint := 'Payload To Encrypt';
      btnECIESEncryptDecrypt.Caption := 'Encrypt Payload with ECIES';
    end;

    TECIESEncryptionMode.Decrypt:
    begin
      edtECIESPrivateKeyPassword.Visible := True;
      edtECIESPrivateKeyPassword.TextHint := 'PrivateKey Password';
      edtECIESKey.TextHint := 'Encrypted PascalCoin Private Key To Use For Decryption';
      edtECIESPayload.TextHint := 'Payload To Decrypt';
      btnECIESEncryptDecrypt.Caption := 'Decrypt Payload with ECIES';
    end;
  end;
end;

procedure TMainForm.cmbPrivateKeyEncryptionModesChange(Sender: TObject);
var
  CurrentlySelected: TPrivateKeyEncryptionMode;
begin
  CurrentlySelected := TPrivateKeyEncryptionMode(GetEnumValue(TypeInfo(TPrivateKeyEncryptionMode), cmbPrivateKeyEncryptionModes.Items[cmbPrivateKeyEncryptionModes.ItemIndex]));
  case CurrentlySelected of
    TPrivateKeyEncryptionMode.Encrypt:
    begin
      edtPrivateKeyPassword.TextHint := 'Encryption Password';
      edtPrivateKey.TextHint := 'Private Key To Encrypt';
      btnEncryptDecryptPrivateKey.Caption := 'Encrypt';
    end;

    TPrivateKeyEncryptionMode.Decrypt:
    begin
      edtPrivateKeyPassword.TextHint := 'Decryption Password';
      edtPrivateKey.TextHint := 'Encrypted PascalCoin Private Key To Decrypt';
      btnEncryptDecryptPrivateKey.Caption := 'Decrypt';
    end;
  end;
end;

procedure TMainForm.btnGenerateKeyPairClick(Sender: TObject);
var
  Logger: TStringList;
begin
  Logger := TStringList.Create();
  try
    TPascalCoinKeyTool.GenerateKeyPairAndLog(TKeyType(GetEnumValue(TypeInfo(TKeyType), cmbKeyTypes.Items[cmbKeyTypes.ItemIndex])), edtEncryptPassword.Text, Logger);
    mmoLoggerMemo.Lines.AddStrings(Logger, False);
  finally
    Logger.Free;
  end;
end;

end.
