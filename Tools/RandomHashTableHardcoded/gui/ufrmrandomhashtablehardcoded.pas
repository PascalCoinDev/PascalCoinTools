unit UFRMRandomHashTableHardcoded;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$I config.inc}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ExtCtrls,
  StdCtrls, UConst, UAccounts, UCrypto, UBaseTypes,
  UPCHardcodedRandomHashTable;

type

  { TFRMRandomHashTableHardcoded }

  TFRMRandomHashTableHardcoded = class(TForm)
    bbGenerateHardcodedFile: TButton;
    bbCheckFile: TButton;
    Label1: TLabel;
    memo: TMemo;
    pnlTop: TPanel;
    procedure bbCheckFileClick(Sender: TObject);
    procedure bbGenerateHardcodedFileClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private

  public

  end;

var
  FRMRandomHashTableHardcoded: TFRMRandomHashTableHardcoded;

implementation

{$R *.lfm}

{ TFRMRandomHashTableHardcoded }

procedure TFRMRandomHashTableHardcoded.FormCreate(Sender: TObject);
begin
  memo.Lines.Clear;
  {$IFDEF TESTNET}
  memo.Lines.Add('Allow read TESTNET Safebox files only (checkpoints)');
  {$ELSE}
  memo.Lines.Add('Allow read PRODUCTION Safebox files only (checkpoints)');
  {$ENDIF}
end;

procedure TFRMRandomHashTableHardcoded.bbGenerateHardcodedFileClick(Sender: TObject);
  function GetProofOfWorkDigest(const operationBlock: TOperationBlock) : TRawBytes;
  var ms : TMemoryStream;
    accKeyRaw : TRawBytes;
  begin
    ms := TMemoryStream.Create;
    try
      // Part 1
      ms.Write(operationBlock.block,Sizeof(operationBlock.block)); // Little endian
      accKeyRaw := TAccountComp.AccountKey2RawString(operationBlock.account_key);
      ms.WriteBuffer(accKeyRaw[Low(accKeyRaw)],Length(accKeyRaw));
      ms.Write(operationBlock.reward,Sizeof(operationBlock.reward)); // Little endian
      ms.Write(operationBlock.protocol_version,Sizeof(operationBlock.protocol_version)); // Little endian
      ms.Write(operationBlock.protocol_available,Sizeof(operationBlock.protocol_available)); // Little endian
      ms.Write(operationBlock.compact_target,Sizeof(operationBlock.compact_target)); // Little endian
      // Part 2
      ms.WriteBuffer(operationBlock.block_payload[Low(operationBlock.block_payload)],Length(operationBlock.block_payload));
      // Part 3
      ms.WriteBuffer(operationBlock.initial_safe_box_hash[Low(operationBlock.initial_safe_box_hash)],length(operationBlock.initial_safe_box_hash));
      ms.WriteBuffer(operationBlock.operations_hash[Low(operationBlock.operations_hash)],length(operationBlock.operations_hash));
      // Note about fee: Fee is stored in 8 bytes (Int64), but only digest first 4 low bytes
      ms.Write(operationBlock.fee,4);
      ms.Write(operationBlock.timestamp,4);
      ms.Write(operationBlock.nonce,4);

      SetLength(Result,ms.Size);
      Move(ms.Memory^,Result[0],ms.Size);

    finally
      ms.Free;
    end;
  end;
var LSaveDialog : TSaveDialog;
  LOpenDialog : TOpenDialog;
  LSafeboxFileName, LHardcodedFilename : String;
  LSafeboxFileStream, LHardcodedFileStream : TFileStream;
  LHardcodedTable : TPCHardcodedRandomHashTable;
  LSafebox : TPCSafeBox;
  LBlockAccount : TBlockAccount;
  LErrors : String;
  i : Integer;
begin
  TCrypto.InitCrypto;

  LOpenDialog := TOpenDialog.Create(Self);
  try
    LOpenDialog.Name:='OpenSafebox1';
    LOpenDialog.Title:='Open Safebox/Checkpoint file';
    LOpenDialog.Filter:='Safebox (*.safebox)|*.safebox|All files (*.*)|*.*';
    If Not LOpenDialog.Execute then Exit;
    LSafeboxFileName := LOpenDialog.FileName;
  finally
    LOpenDialog.Free;
  end;


  LSaveDialog := TSaveDialog.Create(Self);
  try
    LSaveDialog.Name:='SaveHardcoded1';
    LSaveDialog.Title:='Hardcoded RandomHash table file';
    if LSaveDialog.Execute then begin
      LHardcodedFilename := LSaveDialog.FileName;
    end else Exit;
  finally
    LSaveDialog.Free;
  end;


  LHardcodedTable := TPCHardcodedRandomHashTable.Create;
  try
    LSafebox := TPCSafeBox.Create;
    try
      LSafeboxFileStream := TFileStream.Create(LSafeboxFileName,fmOpenRead+fmShareDenyNone);
      try
        if Not LSafebox.LoadSafeBoxFromStream(LSafeboxFileStream,False,LBlockAccount,LErrors) then Raise Exception.Create(LErrors);
      finally
        LSafeboxFileStream.Free;
      end;

      for i:=0 to LSafebox.BlocksCount-1 do begin
        LBlockAccount := LSafebox.Block(i);

        if LBlockAccount.blockchainInfo.protocol_version=CT_PROTOCOL_4 then begin
          LHardcodedTable.AddRandomHash(LBlockAccount.blockchainInfo.proof_of_work,GetProofOfWorkDigest(LBlockAccount.blockchainInfo),False);
        end;
      end;
    finally
      LSafebox.Free;
    end;

    // Save
    LHardcodedFileStream := TFileStream.Create(LHardcodedFilename,fmCreate);
    try
      LHardcodedFileStream.Size:=0;
      LHardcodedTable.SaveToStream(LHardcodedFileStream);
    finally
      LHardcodedFileStream.Free;
    end;

    memo.Lines.Add(bbGenerateHardcodedFile.Caption);
    memo.Lines.Add('Process successfully finalized');
    memo.Lines.Add(Format('Loaded from Safebox file: %s',[LSafeboxFileName]));
    memo.Lines.Add(Format('Saved %d hardcoded values to file: %s',[LHardcodedTable.Count,LHardcodedFilename]));
    memo.Lines.Add(Format('Hardcoded file SHA256 integrity: %s',[LHardcodedTable.GetHardcodedSha256.ToHexaString]));

  finally
    LHardcodedTable.Free;
  end;
end;

procedure TFRMRandomHashTableHardcoded.bbCheckFileClick(Sender: TObject);
var
  LOpenDialog : TOpenDialog;
  LHardcodedFilename : String;
  LHardcodedFileStream : TFileStream;
  LHardcodedTable : TPCHardcodedRandomHashTable;
  LSha256 : TRawBytes;
  i : Integer;
begin
  TCrypto.InitCrypto;

  LOpenDialog := TOpenDialog.Create(Self);
  try
    LOpenDialog.Name:='OpenHardcoded1';
    LOpenDialog.Title:='Open Hardcoded RandomHash table file';
    If Not LOpenDialog.Execute then Exit;
    LHardcodedFilename := LOpenDialog.FileName;
  finally
    LOpenDialog.Free;
  end;


  LHardcodedTable := TPCHardcodedRandomHashTable.Create;
  try
    LHardcodedFileStream := TFileStream.Create(LHardcodedFilename,fmOpenRead+fmShareDenyNone);
    try
      if Not LHardcodedTable.LoadFromStream(LHardcodedFileStream,LSha256) then Raise Exception.Create('Invalid hardcoded file');
    finally
      LHardcodedFileStream.Free;
    end;

    memo.Lines.Add(bbCheckFile.Caption);
    memo.Lines.Add('Process successfully finalized');
    memo.Lines.Add(Format('Loaded %d hardcoded values from file: %s',[LHardcodedTable.Count,LHardcodedFilename]));
    memo.Lines.Add(Format('Hardcoded file SHA256 integrity: %s',[LHardcodedTable.GetHardcodedSha256.ToHexaString]));

  finally
    LHardcodedTable.Free;
  end;
end;

procedure TFRMRandomHashTableHardcoded.FormDestroy(Sender: TObject);
begin
end;

end.

