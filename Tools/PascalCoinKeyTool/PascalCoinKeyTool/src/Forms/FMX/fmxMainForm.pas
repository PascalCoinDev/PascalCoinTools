/// <summary>
///   <para>
///     Delphi Firemonkey Multi Device Interface for PascalCoinKeyTool by
///     Ugochukwu Mmaduekwe.
///   </para>
///   <para>
///     Copyright (c) 2018 Ugochukwu Mmaduekwe
///   </para>
///   <para>
///     Copyright (c) 2019 Russell Weetch
///   </para>
///   <para>
///     # License <br /><br />This "Software" is Licensed Under **`MIT
///     License (MIT)`** <br />
///   </para>
/// </summary>
unit fmxMainForm;


interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.ListBox,
  FMX.Layouts, FMX.TabControl, FMX.ScrollBox, FMX.Memo,
  FMX.Controls.Presentation, FMX.Edit, FMX.StdCtrls, FMX.EditBox, FMX.SpinBox;

type
  TMainForm = class(TForm)
    TabControl1: TTabControl;
    TabItem1: TTabItem;
    TabItem2: TTabItem;
    Layout1: TLayout;
    cmbKeyTypes: TComboBox;
    edtEncryptPassword: TEdit;
    mmoLoggerMemo: TMemo;
    Button1: TButton;
    Button2: TButton;
    speIterationCount: TSpinBox;
    edtMessageToSign: TEdit;
    Label1: TLabel;
    mmoStressTestLoggerMemo: TMemo;
    Button3: TButton;
    btnStressTest: TButton;
    TabItem3: TTabItem;
    TabItem4: TTabItem;
    TabItem5: TTabItem;
    cmbPrivateKeyEncryptionModes: TComboBox;
    edtPrivateKeyPassword: TEdit;
    mmoPrivateKeyLoggerMemo: TMemo;
    Button4: TButton;
    btnEncryptDecryptPrivateKey: TButton;
    edtPrivateKey: TEdit;
    edtAESPayloadPassword: TEdit;
    cmbAESEncryptionModes: TComboBox;
    edtAESPayload: TEdit;
    mmoAESLoggerMemo: TMemo;
    Button5: TButton;
    btnAESEncryptDecrypt: TButton;
    edtECIESPrivateKeyPassword: TEdit;
    cmbECIESEncryptionModes: TComboBox;
    edtECIESKey: TEdit;
    mmoECIESLoggerMemo: TMemo;
    Button6: TButton;
    btnECIESEncryptDecrypt: TButton;
    edtECIESPayload: TEdit;
    KeyType: TLabel;
    procedure btnAESEncryptDecryptClick(Sender: TObject);
    procedure btnECIESEncryptDecryptClick(Sender: TObject);
    procedure btnEncryptDecryptPrivateKeyClick(Sender: TObject);
    procedure btnStressTestClick(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure Button5Click(Sender: TObject);
    procedure Button6Click(Sender: TObject);
    procedure cmbAESEncryptionModesChange(Sender: TObject);
    procedure cmbECIESEncryptionModesChange(Sender: TObject);
    procedure cmbKeyTypesChange(Sender: TObject);
    procedure cmbPrivateKeyEncryptionModesChange(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
    type
    {$SCOPEDENUMS ON}
    TPrivateKeyEncryptionMode = (Encrypt, Decrypt);
    TECIESEncryptionMode = (Encrypt, Decrypt);
    TAESEncryptionMode = (Encrypt, Decrypt);
    {$SCOPEDENUMS OFF}
  public
    { Public declarations }
  end;

var
  MainForm: TMainForm;

implementation

{$R *.fmx}

uses uPascalCoinKeyTool, TypInfo, System.Rtti;

procedure TMainForm.btnAESEncryptDecryptClick(Sender: TObject);
var
  CurrentlySelected: TAESEncryptionMode;
  Logger: TStringList;
  Payload: string;
begin
  CurrentlySelected := TRttiEnumerationType.GetValue<TAESEncryptionMode>(cmbAESEncryptionModes.Items[cmbAESEncryptionModes.ItemIndex]);
  case CurrentlySelected of
    TAESEncryptionMode.Encrypt:
    begin
      Payload := Trim(edtAESPayload.Text);
      if (Payload <> '') then
      begin
        Logger := TStringList.Create();
        try
          TPascalCoinKeyTool.EncryptPascalCoinAESPayload(edtAESPayloadPassword.Text, Payload, Logger);
          mmoAESLoggerMemo.Lines.AddStrings(Logger);
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
          mmoAESLoggerMemo.Lines.AddStrings(Logger);
        finally
          Logger.Free;
        end;
      end;
    end;
  end;
end;

procedure TMainForm.btnECIESEncryptDecryptClick(Sender: TObject);
var
  CurrentlySelected: TECIESEncryptionMode;
  SelectedKeyType: TKeyType;
  Logger: TStringList;
  PascalCoinPublicKey, EncryptedPascalCoinPrivateKey, Payload: string;
begin
  CurrentlySelected := TRttiEnumerationType.GetValue<TECIESEncryptionMode>(
    cmbECIESEncryptionModes.Items[cmbECIESEncryptionModes.ItemIndex]);
  SelectedKeyType := TRttiEnumerationType.GetValue<TKeyType>(
    cmbKeyTypes.Items[cmbKeyTypes.ItemIndex]);

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
          mmoECIESLoggerMemo.Lines.AddStrings(Logger);
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
          mmoECIESLoggerMemo.Lines.AddStrings(Logger);
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
      SelectedKeyType := TRttiEnumerationType.GetValue<TKeyType>(cmbKeyTypes.Items[cmbKeyTypes.ItemIndex]);
      PrivateKeyToEncrypt := Trim(edtPrivateKey.Text);
      if PrivateKeyToEncrypt <> '' then
      begin
        Logger := TStringList.Create();
        try
          TPascalCoinKeyTool.EncryptPascalCoinPrivateKey(SelectedKeyType,
             PrivateKeyToEncrypt, edtPrivateKeyPassword.Text, Logger);
          mmoPrivateKeyLoggerMemo.Lines.AddStrings(Logger);
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
          TPascalCoinKeyTool.DecryptPascalCoinPrivateKey(EncryptedPascalCoinPrivateKey,
            edtPrivateKeyPassword.Text, Logger);
          mmoPrivateKeyLoggerMemo.Lines.AddStrings(Logger);
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
  lIterations: Integer;
begin
  SelectedKeyType := TKeyType(GetEnumValue(TypeInfo(TKeyType), cmbKeyTypes.Items[cmbKeyTypes.ItemIndex]));
  lIterations := Trunc(speIterationCount.Value);
  Logger := TStringList.Create();
  try
    btnStressTest.Enabled := False;
    TPascalCoinKeyTool.Generate_Recreate_Sign_Verify_ECDSA_Stress_Test(SelectedKeyType,
       edtMessageToSign.Text, lIterations, Logger);
    mmoStressTestLoggerMemo.Lines.AddStrings(Logger);
  finally
    Logger.Free;
    btnStressTest.Enabled := True;
  end;
end;

procedure TMainForm.Button1Click(Sender: TObject);
begin
  mmoLoggerMemo.Lines.Clear;
end;

procedure TMainForm.Button2Click(Sender: TObject);
var
  Logger: TStringList;
  lKeyType: TKeyType;
begin
  Logger := TStringList.Create();
  try
    lKeyType := TRttiEnumerationType.GetValue<TKeyType>(cmbKeyTypes.Items[cmbKeyTypes.ItemIndex]);
    TPascalCoinKeyTool.GenerateKeyPairAndLog(lKeyType, edtEncryptPassword.Text, Logger);
    mmoLoggerMemo.Lines.AddStrings(Logger);
  finally
    Logger.Free;
  end;
end;

procedure TMainForm.Button3Click(Sender: TObject);
begin
  mmoStressTestLoggerMemo.DeleteSelection;
end;

procedure TMainForm.Button4Click(Sender: TObject);
begin
  mmoPrivateKeyLoggerMemo.ClearContent;
end;

procedure TMainForm.Button5Click(Sender: TObject);
begin
  mmoAESLoggerMemo.ClearContent;
end;

procedure TMainForm.Button6Click(Sender: TObject);
begin
  mmoECIESLoggerMemo.ClearContent;
end;

procedure TMainForm.cmbAESEncryptionModesChange(Sender: TObject);
var
  CurrentlySelected: TAESEncryptionMode;
begin
  CurrentlySelected := TRttiEnumerationType.GetValue<TAESEncryptionMode>(cmbAESEncryptionModes.Items[cmbAESEncryptionModes.ItemIndex]);
  case CurrentlySelected of
    TAESEncryptionMode.Encrypt:
    begin
      edtAESPayloadPassword.TextPrompt := 'Encryption Password';
      edtAESPayload.TextPrompt := 'Payload To Encrypt';
      btnAESEncryptDecrypt.Text := 'Encrypt Payload with AES';
    end;

    TAESEncryptionMode.Decrypt:
    begin
      edtAESPayloadPassword.TextPrompt := 'Decryption Password';
      edtAESPayload.TextPrompt := 'Payload To Decrypt';
      btnAESEncryptDecrypt.Text := 'Decrypt Payload with AES';
    end;
  end;
end;

procedure TMainForm.cmbECIESEncryptionModesChange(Sender: TObject);
var
  CurrentlySelected: TECIESEncryptionMode;
begin
  CurrentlySelected := TRttiEnumerationType.GetValue<TECIESEncryptionMode>(
    cmbECIESEncryptionModes.Items[cmbECIESEncryptionModes.ItemIndex]);
  case CurrentlySelected of
    TECIESEncryptionMode.Encrypt:
    begin
      edtECIESPrivateKeyPassword.Text := '';
      edtECIESPrivateKeyPassword.TextPrompt := '';
      edtECIESPrivateKeyPassword.Visible := False;
      edtECIESKey.TextPrompt := 'PascalCoin Public Key (In Base58) To Use For Encryption';
      edtECIESPayload.TextPrompt := 'Payload To Encrypt';
      btnECIESEncryptDecrypt.Text := 'Encrypt Payload with ECIES';
    end;

    TECIESEncryptionMode.Decrypt:
    begin
      edtECIESPrivateKeyPassword.Visible := True;
      edtECIESPrivateKeyPassword.TextPrompt := 'PrivateKey Password';
      edtECIESKey.TextPrompt := 'Encrypted PascalCoin Private Key To Use For Decryption';
      edtECIESPayload.TextPrompt := 'Payload To Decrypt';
      btnECIESEncryptDecrypt.Text := 'Decrypt Payload with ECIES';
    end;
  end;
end;

procedure TMainForm.cmbKeyTypesChange(Sender: TObject);
var
  CurrentlySelected: TKeyType;
begin
  CurrentlySelected := TKeyType(GetEnumValue(TypeInfo(TKeyType),
    cmbKeyTypes.Items[cmbKeyTypes.ItemIndex]));
  KeyType.Text := TRttiEnumerationType.GetName<TKeyType>(CurrentlySelected);
end;

procedure TMainForm.cmbPrivateKeyEncryptionModesChange(Sender: TObject);
var
  CurrentlySelected: TPrivateKeyEncryptionMode;
begin
  CurrentlySelected := TPrivateKeyEncryptionMode(GetEnumValue(TypeInfo(TPrivateKeyEncryptionMode), cmbPrivateKeyEncryptionModes.Items[cmbPrivateKeyEncryptionModes.ItemIndex]));
  case CurrentlySelected of
    TPrivateKeyEncryptionMode.Encrypt:
    begin
      edtPrivateKeyPassword.TextPrompt := 'Encryption Password';
      edtPrivateKey.TextPrompt := 'Private Key To Encrypt';
      btnEncryptDecryptPrivateKey.Text := 'Encrypt';
    end;

    TPrivateKeyEncryptionMode.Decrypt:
    begin
      edtPrivateKeyPassword.TextPrompt := 'Decryption Password';
      edtPrivateKey.TextPrompt := 'Encrypted PascalCoin Private Key To Decrypt';
      btnEncryptDecryptPrivateKey.Text := 'Decrypt';
    end;
  end;
end;

procedure TMainForm.FormCreate(Sender: TObject);
var
  KeyType: TKeyType;
  lName: string;
  PrivateKeyEncryptionMode: TPrivateKeyEncryptionMode;
  ECIESEncryptionMode: TECIESEncryptionMode;
  AESEncryptionMode: TAESEncryptionMode;
begin
  cmbKeyTypes.Clear;

  for KeyType := Low(TKeyType) to High(TKeyType) do
  begin
    lName := TRttiEnumerationType.GetName<TKeyType>(KeyType);
    cmbKeyTypes.Items.Add(lName);
  end;
  cmbKeyTypes.ItemIndex := 0;
  cmbKeyTypesChange(Self);

  cmbPrivateKeyEncryptionModes.Clear;
  for PrivateKeyEncryptionMode := Low(TPrivateKeyEncryptionMode) to High(TPrivateKeyEncryptionMode) do
  begin
    lName := TRttiEnumerationType.GetName<TPrivateKeyEncryptionMode>(PrivateKeyEncryptionMode);
    cmbPrivateKeyEncryptionModes.Items.Add(lName);
  end;

  cmbPrivateKeyEncryptionModes.ItemIndex := 0;
  cmbPrivateKeyEncryptionModesChange(Self);

  cmbECIESEncryptionModes.Clear;
  for ECIESEncryptionMode := Low(TECIESEncryptionMode) to High(TECIESEncryptionMode) do
  begin
    lName := TRttiEnumerationType.GetName<TECIESEncryptionMode>(ECIESEncryptionMode);
    cmbECIESEncryptionModes.Items.Add(lName);
  end;
  cmbECIESEncryptionModes.ItemIndex := 0;
  cmbECIESEncryptionModesChange(Self);

  cmbAESEncryptionModes.Clear;
  for AESEncryptionMode := Low(TAESEncryptionMode) to High(TAESEncryptionMode) do
    begin
      lName := TRttiEnumerationType.GetName<TAESEncryptionMode>(AESEncryptionMode);
      cmbAESEncryptionModes.Items.Add(lName);
    end;
  cmbAESEncryptionModes.ItemIndex := 0;
  cmbAESEncryptionModesChange(Self);

end;

end.
