unit USQLiteStorage;

{ Copyright (c) 2018-2019 by Albert Molina

  Distributed under the MIT software license, see the accompanying file LICENSE
  or visit http://www.opensource.org/licenses/mit-license.php.

  This unit is a part of the PascalCoin Project, an infinitely scalable
  cryptocurrency. Find us here:
  Web: https://www.pascalcoin.org
  Source: https://github.com/PascalCoin/PascalCoin

  If you like it, consider a donation using Bitcoin:
  16K3HCZRhFUtM8GdWRcfKeaa6KsuyxZaYk

  THIS LICENSE HEADER MUST NOT BE REMOVED.


  This unit is a Implementation of the TStorage class that allows to save
  PascalCoin blockchain in a SQLite database.
  When saving in a SQLite Database, it should be easy to find information
  about historical operations instead of use full OpHash traditional value.

  In the initial implementation of TStorage class (TFileStorage) there is no
  index to find a OpHash when "block number" is not provided inside the
  OpHash field (note, OpHash field info are 4 bytes for block number as a optional value)
  Also, in TFileStorage there is no index to find all related operations
  to a single account.
  All this kind of information should be better to find in a SQL like database

  This file is a INITIAL proposal of a SQL like style database for PascalCoin


  Current status: IN DEVELOPMENT

  Version 0.1 - 2019-01-17
  Initial publish

}

{$IFDEF FPC}
  {$mode delphi}
{$ENDIF}

interface

uses
  Classes, SysUtils, UBlockchain, UThread, UCrypto, math, UAccounts, ULog, SQLite3, SQLite3Wrap, SQLite3Utils, UConst, UBaseTypes;

const
  CT_TblName_BlockChain = 'tblockchain'; // This table stores each Block info and also RAW data of the block
  CT_TblName_CheckPoint = 'tcheckpoint'; // This table stores each saved checkpoint (Safebox)
  CT_TblName_Accounts   = 'taccounts';   // This table stores each account with all operations that has affect on it

  CT_TblFld_BlockChain_block = 'block';
  CT_TblFld_BlockChain_orphan = 'orphan';
  CT_TblFld_BlockChain_accountkey = 'accountkey';
  CT_TblFld_BlockChain_reward = 'reward';
  CT_TblFld_BlockChain_fee = 'fee';
  CT_TblFld_BlockChain_protocol_version = 'protocol_version';
  CT_TblFld_BlockChain_protocol_available = 'protocol_available';
  CT_TblFld_BlockChain_timestamp = 'timestamp';
  CT_TblFld_BlockChain_target = 'target';
  CT_TblFld_BlockChain_nonce = 'nonce';
  CT_TblFld_BlockChain_rawpayload = 'rawpayload';
  CT_TblFld_BlockChain_safe_box_hash = 'safe_box_hash';
  CT_TblFld_BlockChain_operations_hash = 'operations_hash';
  CT_TblFld_BlockChain_proof_of_work = 'proof_of_work';
  CT_TblFld_BlockChain_operations_count = 'operations_count';
  CT_TblFld_BlockChain_volume = 'volume';
  CT_TblFld_BlockChain_rawdata = 'rawdata';

  CT_TblFld_Account_block = 'block';
  CT_TblFld_Account_orphan = 'orphan';
  CT_TblFld_Account_nopblock = 'nopblock';
  CT_TblFld_Account_right_ophash = 'right_ophash';
  CT_TblFld_Account_account = 'account';
  CT_TblFld_Account_n_operation = 'n_operation';
  CT_TblFld_Account_amount = 'amount'; // Positive = Receive, Negative = Send, 0 = None
  CT_TblFld_Account_hexa_payload = 'hexa_payload';
  CT_TblFld_Account_op_text = 'op_text';
  CT_TblFld_Account_optype = 'optype';

  CT_TblFld_CheckPoint_id = 'idcheckpoint';
  CT_TblFld_CheckPoint_block = 'block';
  CT_TblFld_CheckPoint_rawdata = 'rawdata';
  CT_TblFld_CheckPoint_orphan = 'orphan';


type

  { TSQLiteStorage }

  TSQLiteStorage = Class(TStorage)
  private
    FSQLiteFileName: String;
    FStorageLock : TPCCriticalSection;
    FDatabase : TSQLite3Database;
    FIsCopiedDatabase : Boolean;
    procedure SetSQLiteFileName(AValue: String);
    function GetOrphanWhere(const AOrphanValue : TOrphan) : String;
    class var SQLiteFormatSettings : TFormatSettings;
    function InternalExecuteSQL(ADatabase : TSQLite3Database; const sql : String) : Integer;
    Procedure InternalSaveSafebox(ADatabase : TSQLite3Database; AOrphanValue : TOrphan; NBlock : Cardinal; rawData: Pointer; rawSize : Integer);
    Procedure InternalDeleteBlocks(ADatabase : TSQLite3Database; AOrphanValue : TOrphan; start_delete_block : Cardinal);
    Function DoLoadBlockChainExt(Operations : TPCOperationsComp; Block : Cardinal; const AOrphanValue : TOrphan) : Boolean;
    Function DoSaveBlockChainExt(Operations : TPCOperationsComp; const AOrphanValue : TOrphan) : Boolean;
  protected
    Function DoLoadBlockChain(Operations : TPCOperationsComp; Block : Cardinal) : Boolean; override;
    Function DoSaveBlockChain(Operations : TPCOperationsComp) : Boolean; override;
    Function DoMoveBlockChain(Start_Block : Cardinal; Const DestOrphan : TOrphan; DestStorage : TStorage) : Boolean; override;
    Function DoSaveBank : Boolean; override;
    Function DoRestoreBank(max_block : Int64; restoreProgressNotify : TProgressNotify) : Boolean; override;
    Procedure DoDeleteBlockChainBlocks(StartingDeleteBlock : Cardinal); override;
    Function DoBlockExists(Block : Cardinal) : Boolean; override;
    function GetFirstBlockNumber: Int64; override;
    function GetLastBlockNumber: Int64; override;
    function DoInitialize : Boolean; override;
    Function DoCreateSafeBoxStream(blockCount : Cardinal) : TStream; override;
    Procedure DoEraseStorage; override;
    Procedure DoSavePendingBufferOperations(OperationsHashTree : TOperationsHashTree); override;
    Procedure DoLoadPendingBufferOperations(OperationsHashTree : TOperationsHashTree); override;
  public
    Constructor Create(AOwner : TComponent); Override;
    Destructor Destroy; Override;
    Procedure CopyConfiguration(Const CopyFrom : TStorage); override;
    Function HasUpgradedToVersion2 : Boolean; override;
    Procedure CleanupVersion1Data; override;
    property SQLiteFileName : String read FSQLiteFileName write SetSQLiteFileName;
    //
    function LockDatabase : TSQLite3Database;
    procedure UnlockDatabase;
  End;


implementation

{ TSQLiteStorage }

function TSQLiteStorage.LockDatabase: TSQLite3Database;
begin
  FStorageLock.Acquire;
  Try
    If Not Assigned(FDatabase) then begin
      FIsCopiedDatabase := False;
      If FSQLiteFileName='' then Raise Exception.Create('Need Database file name');
      If not ForceDirectories(ExtractFileDir(FSQLiteFileName)) then Raise Exception.Create('Cannot create data dir '+ExtractFileDir(FSQLiteFileName));
      FDatabase := TSQLite3Database.Create;
      if ReadOnly then FDatabase.Open(FSQLiteFileName,SQLITE_OPEN_READONLY)
      else FDatabase.Open(FSQLiteFileName);
    end;
  Except
    FreeAndNil(FDatabase);
    FStorageLock.Release;
    Raise;
  end;
  Result := FDatabase;
end;

procedure TSQLiteStorage.SetSQLiteFileName(AValue: String);
begin
  if FSQLiteFileName=AValue then Exit;
  FStorageLock.Acquire;
  Try
    FSQLiteFileName:=AValue;
    FreeAndNil(FDatabase);
  finally
    FStorageLock.Release;
  end;
end;

procedure TSQLiteStorage.UnlockDatabase;
begin
  FStorageLock.Release;
end;

function TSQLiteStorage.GetOrphanWhere(const AOrphanValue : TOrphan) : String;
begin
  if (AOrphanValue<>'') then Result := 'orphan = '''+AOrphanValue+''''
  else Result := 'orphan IS NULL';
end;

function TSQLiteStorage.InternalExecuteSQL(ADatabase : TSQLite3Database; const sql: String): Integer;
begin
  try
    ADatabase.Execute(sql);
    Result := sqlite3_total_changes(ADatabase.Handle);
  except
    On E:Exception do begin
      TLog.NewLog(lterror,ClassName,'Error ('+E.ClassName+'):'+E.Message+' executing SQL: '+sql);
      E.Message := E.Message + #10+'SQL:'+#10+sql;
      Raise;
    end;
  end;
end;

procedure TSQLiteStorage.InternalSaveSafebox(ADatabase: TSQLite3Database; AOrphanValue: TOrphan; NBlock: Cardinal; rawData: Pointer; rawSize : Integer);
var stat : TSQLite3Statement;
  nStepResult : Integer;
begin
  InternalExecuteSQL(ADatabase, Format('DELETE FROM %s WHERE (%s) AND (%s=%d)',
    [CT_TblName_CheckPoint,GetOrphanWhere(AOrphanValue),CT_TblFld_CheckPoint_block,NBlock]));
  stat := ADatabase.Prepare(Format('INSERT INTO %s (%s,%s,%s) VALUES (?,?,?)',[
      CT_TblName_CheckPoint,CT_TblFld_CheckPoint_block,CT_TblFld_CheckPoint_orphan,CT_TblFld_CheckPoint_rawdata]));
  try
    stat.BindInt(1,NBlock);
    if AOrphanValue<>'' then stat.BindText(2,AOrphanValue)
    else stat.BindNull(2);
    stat.BindBlob(3,rawData,rawSize);
    nStepResult := stat.Step;
    if nStepResult<>SQLITE_DONE then Raise Exception.Create(Format('Invalid SQLITE step result saving Safebox(%d):%d at Orphan:%s',[NBlock,nStepResult,AOrphanValue]));
  finally
    stat.Free;
  end;
end;

procedure TSQLiteStorage.InternalDeleteBlocks(ADatabase: TSQLite3Database; AOrphanValue: TOrphan; start_delete_block: Cardinal);
var ndelblocks,
  ndelaccounts : Integer;
begin
  // Delete itself and higher blocks
  ndelblocks := InternalExecuteSQL(ADatabase,'DELETE FROM '+CT_TblName_BlockChain+' WHERE ('+CT_TblFld_BlockChain_block+'>='+IntToStr(start_delete_block)+') AND ('+GetOrphanWhere(AOrphanValue)+')');
  // Delete operations at accounts
  ndelaccounts := InternalExecuteSQL(ADatabase,'DELETE FROM '+CT_TblName_Accounts+' WHERE ('+CT_TblFld_Account_block+'>='+IntToStr(start_delete_block)+') AND ('+GetOrphanWhere(AOrphanValue)+')');
  TLog.NewLog(ltdebug,ClassName,Format('Deleted Block %d (deleted %d blocks %d account operations) Orphan:%s',
    [start_delete_block,ndelblocks,ndelaccounts,AOrphanValue]));
end;

function TSQLiteStorage.DoLoadBlockChainExt(Operations: TPCOperationsComp; Block: Cardinal; const AOrphanValue: TOrphan): Boolean;
Var sqls : TSQLite3Statement;
  ms : TMemoryStream;
  errors : AnsiString;
begin
  Result := False;
  LockDatabase;
  try
    sqls := FDatabase.Prepare('SELECT '+CT_TblFld_BlockChain_rawdata+' FROM '+CT_TblName_BlockChain+
         ' WHERE ('+CT_TblFld_BlockChain_block+'='+IntToStr(Block)+') AND ('+GetOrphanWhere(AOrphanValue)+')');
    if sqls.Step = SQLITE_ROW then begin
      ms := TMemoryStream.Create;
      try
        ms.Write(sqls.ColumnBlob(0)^,sqls.ColumnBytes(0));
        ms.Position:=0;
        Result := Operations.LoadBlockFromStorage(ms,errors);
      finally
        ms.Free;
      end;
    end;
  finally
    UnlockDatabase;
  end;
end;

function TSQLiteStorage.DoLoadBlockChain(Operations: TPCOperationsComp; Block: Cardinal): Boolean;
begin
  try
    Result := DoLoadBlockChainExt(Operations,Block,Orphan);
  Except
    On E:Exception do begin
      TLog.NewLog(lterror,ClassName,Format('Error loading block %d (%s):%s',[Block,E.ClassName,E.Message]));
      Raise;
    end;
  end;
end;

function TSQLiteStorage.DoSaveBlockChain(Operations: TPCOperationsComp): Boolean;
begin
  try
    Result := DoSaveBlockChainExt(Operations,Orphan);
  Except
    On E:Exception do begin
      TLog.NewLog(lterror,ClassName,Format('Error saving block %d (%s):%s',[Operations.OperationBlock.block,E.ClassName,E.Message]));
      Raise;
    end;
  end;
end;

function TSQLiteStorage.DoSaveBlockChainExt(Operations: TPCOperationsComp; const AOrphanValue: TOrphan): Boolean;
  function SQLV_Orphan : String;
  begin
    if AOrphanValue<>'' then Result := ''''+AOrphanValue+''''
    else Result := 'NULL';
  end;
  function SQLV_Pascurrency(internal_money : Int64) : String;
  begin
    Result := FormatFloat('0.####',internal_money / 10000,SQLiteFormatSettings);
  end;
  function SQLV_Integer(int_value : Int64) : String;
  begin
    Result := IntToStr(int_value);
  end;
  function SQLV_Integer_Or_Null(int_value : Int64) : String;
  begin
    if int_value<>0 then Result := IntToStr(int_value)
    else Result := 'NULL';
  end;
  function SQLV_String(value : String) : String;
  var i : Integer;
  begin
    if (length(value)>0) then begin
      i := 1;
      repeat
        if (value[i]='''') then begin
          value := copy(value,1,i)+''''+copy(value,i+1,length(value));
          inc(i);
        end;
        inc(i);
      until (i>length(value));
    end;
    Result := ''''+value+'''';
  end;
  function SQLV_String_Or_Null(value : String) : String;
  begin
    if value='' then Result := 'NULL'
    else Result := SQLV_String(value);
  end;

  procedure SaveOperationsTable;
  var iOp : Integer;
    op : TPCOperation;
    laccounts : TList;
    iAccount : Integer;
    step, sqltxt : String;
    stat_accounts : TSQLite3Statement;
  begin
    step := '';
    try
      stat_accounts := FDatabase.Prepare(Format('INSERT INTO %s (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) VALUES (?,?,?,?,?,?,?,?,?,?)',
                [CT_TblName_Accounts,
                //
                CT_TblFld_Account_block, CT_TblFld_Account_nopblock,
                CT_TblFld_Account_right_ophash,
                CT_TblFld_Account_account, CT_TblFld_Account_n_operation,
                CT_TblFld_Account_amount, CT_TblFld_Account_hexa_payload,
                CT_TblFld_Account_op_text, CT_TblFld_Account_optype,
                CT_TblFld_Account_orphan]));
      try
        for iOp:=0 to Operations.Count-1 do begin
          op := Operations.Operation[iOp];
          // Table Accounts only has data of NON orphan accounts operations
          laccounts := TList.Create;
          Try
            step := Format('Operation %d/%d Get Affected',[iOp+1,Operations.Count]);
            op.AffectedAccounts(laccounts);
            for iAccount:=0 to laccounts.Count-1 do begin
              step := Format('Operation %d/%d accounts:%d/%d',[iOp+1,Operations.Count,iAccount+1,laccounts.Count]);
              stat_accounts.BindInt(1,Operations.OperationBlock.block);
              stat_accounts.BindInt(2,iOp+1);
              stat_accounts.BindText(3,Copy(op.OperationHashAsHexa(op.OperationHashValid(op,0)),9,56));
              stat_accounts.BindInt(4,PtrInt(laccounts[iAccount]));
              if op.GetAccountN_Operation(PtrInt(laccounts[iAccount]))>0 then stat_accounts.BindInt(5,op.GetAccountN_Operation(PtrInt(laccounts[iAccount])))
              else stat_accounts.BindNull(5);
              stat_accounts.BindDouble(6,RoundTo( op.OperationAmountByAccount( PtrInt(laccounts[iAccount]) ) / 10000,-4));
              stat_accounts.BindText(7,TCrypto.ToHexaString(op.OperationPayload));
              stat_accounts.BindText(8,op.ToString);
              stat_accounts.BindInt(9,op.OpType);
              if (AOrphanValue<>'') then stat_accounts.BindText(10,AOrphanValue)
              else stat_accounts.BindNull(10);
              stat_accounts.StepAndReset;
            end;
          finally
            laccounts.Free;
          end;
        end; // for
      finally
        stat_accounts.Free;
      end;
    except
      on E:Exception do begin
        E.Message := E.Message +' step: '+step+'  SQL:'+sqltxt;
        Raise;
      end;
    end;
  end;

Var ms : TMemoryStream;
  bss : TSQLite3Statement;
  i : Integer;
begin
  Result := False;
  LockDatabase;
  try
    FDatabase.BeginTransaction;
    try
      // Blockchain
      InternalDeleteBlocks(FDatabase,AOrphanValue,Operations.OperationBlock.block);
      //
      // Add blockchain
      //
      bss := FDatabase.Prepare(Format('INSERT INTO %s (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,?)',
        [CT_TblName_BlockChain,
         //
         CT_TblFld_BlockChain_block,CT_TblFld_BlockChain_accountkey,CT_TblFld_BlockChain_reward,
         CT_TblFld_BlockChain_fee,CT_TblFld_BlockChain_protocol_version,CT_TblFld_BlockChain_protocol_available,
         CT_TblFld_BlockChain_timestamp,CT_TblFld_BlockChain_target,CT_TblFld_BlockChain_nonce,
         CT_TblFld_BlockChain_rawpayload,CT_TblFld_BlockChain_safe_box_hash,CT_TblFld_BlockChain_operations_hash,
         CT_TblFld_BlockChain_proof_of_work,CT_TblFld_BlockChain_orphan,CT_TblFld_BlockChain_operations_count,
         CT_TblFld_BlockChain_volume,CT_TblFld_BlockChain_rawdata,
         //
         SQLV_Integer(Operations.OperationBlock.block),
         SQLV_String( TCrypto.ToHexaString( TAccountComp.AccountKey2RawString(Operations.OperationBlock.account_key)) ),
         SQLV_Pascurrency( Operations.OperationBlock.reward ),
         SQLV_Pascurrency( Operations.OperationBlock.fee ),
         SQLV_Integer(Operations.OperationBlock.protocol_version),
         SQLV_Integer(Operations.OperationBlock.protocol_available),
         SQLV_Integer(Operations.OperationBlock.timestamp),
         SQLV_String(IntToHex(Operations.OperationBlock.compact_target,8)),
         SQLV_Integer(Operations.OperationBlock.nonce),
         SQLV_String(Operations.OperationBlock.block_payload.ToString ),
         SQLV_String(TCrypto.ToHexaString(Operations.OperationBlock.initial_safe_box_hash)),
         SQLV_String(TCrypto.ToHexaString(Operations.OperationBlock.operations_hash)),
         SQLV_String(TCrypto.ToHexaString(Operations.OperationBlock.proof_of_work)),
         SQLV_String_or_null( AOrphanValue ),
         SQLV_Integer(Operations.Count),
         SQLV_Pascurrency( Operations.OperationsHashTree.TotalAmount )
         ]));
      ms := TMemoryStream.Create;
      try
        Operations.SaveBlockToStorage(ms);
        bss.BindBlob(1,ms.Memory,ms.Size);
      finally
        ms.Free;
      end;
      bss.StepAndReset;
      // Add Operations
      SaveOperationsTable;
      // Commit
      FDatabase.Commit;
      Result := True;
      TLog.NewLog(ltdebug,ClassName,Format('Saved Block %d with %d operations Orphan:%s',
        [Operations.OperationBlock.block,Operations.Count,AOrphanValue]));
    except
      FDatabase.Rollback;
      Result := False;
      Raise;
    end;
  finally
    UnlockDatabase;
  end;
end;

function TSQLiteStorage.DoMoveBlockChain(Start_Block: Cardinal; const DestOrphan: TOrphan; DestStorage: TStorage): Boolean;
  procedure AutomaticMove;
    procedure CheckDone(stepResult : Integer);
    begin
      If stepResult<>SQLITE_DONE then Raise Exception.Create('Step result<>SQLITE_DONE -> '+IntToStr(stepResult));
    end;
  var stat : TSQLite3Statement;
  begin
    // Move all data from "Orphan" to "DestOrphan"
    FDatabase.BeginTransaction;
    try
      // Table Blockchain
      // Delete current data with block >= Start_block at DestOrphan
      InternalExecuteSQL(FDatabase, Format('DELETE FROM %s WHERE (%s) AND (%s>=%d)',
        [CT_TblName_BlockChain,GetOrphanWhere(DestOrphan),CT_TblFld_BlockChain_block,Start_Block]));
      // Move from all blocks >= Start_block from "Orphan" to "DestOrphan"
      stat := FDatabase.Prepare(Format('UPDATE %s=? FROM %s WHERE (%s) AND (%s>=%d)',[
        CT_TblFld_BlockChain_orphan,CT_TblName_BlockChain,GetOrphanWhere(Orphan),
        CT_TblFld_BlockChain_block,Start_Block]));
      try
        if DestOrphan='' then stat.BindNull(1)
        else stat.BindText(1,DestOrphan);
        CheckDone(stat.StepAndReset);
      finally
        stat.Free;
      end;
      // Table Account operations
      // Delete current data with block >= Start_block at DestOrphan
      InternalExecuteSQL(FDatabase,Format('DELETE FROM %s WHERE (%s) AND (%s>=%d)',
        [CT_TblName_Accounts,GetOrphanWhere(DestOrphan),CT_TblFld_Account_block,Start_Block]));
      // Move from all blocks >= Start_block from "Orphan" to "DestOrphan"
      stat := FDatabase.Prepare(Format('UPDATE %s=? FROM %s WHERE (%s) AND (%s>=%d)',[
        CT_TblFld_Account_orphan,CT_TblName_Accounts,GetOrphanWhere(Orphan),
        CT_TblFld_Account_block,Start_Block]));
      try
        if DestOrphan='' then stat.BindNull(1)
        else stat.BindText(1,DestOrphan);
        CheckDone(stat.StepAndReset);
      finally
        stat.Free;
      end;
      // Table Checkpoints
      // Delete current data with block >= Start_block at DestOrphan
      InternalExecuteSQL(FDatabase,Format('DELETE FROM %s WHERE (%s) AND (%s>=%d)',
        [CT_TblName_CheckPoint,GetOrphanWhere(DestOrphan),CT_TblFld_CheckPoint_block,Start_Block]));
      // Move from all blocks >= Start_block from "Orphan" to "DestOrphan"
      stat := FDatabase.Prepare(Format('UPDATE %s=? FROM %s WHERE (%s) AND (%s>=%d)',[
        CT_TblFld_CheckPoint_orphan,CT_TblName_CheckPoint,GetOrphanWhere(Orphan),
        CT_TblFld_CheckPoint_block,Start_Block]));
      try
        if DestOrphan='' then stat.BindNull(1)
        else stat.BindText(1,DestOrphan);
        CheckDone(stat.StepAndReset);
      finally
        stat.Free;
      end;
      //
      FDatabase.Commit;
    Except
      FDatabase.Rollback;
      Raise;
    end;
  end;

Var dest : TSQLiteStorage;
begin
  Result := False;
  Try
    LockDatabase;
    try
      if (Assigned(DestStorage)) then begin
        if Not (DestStorage is TSQLiteStorage) then Raise Exception.Create('Invalid dest storage class '+DestStorage.ClassName);
        dest := TSQLiteStorage(DestStorage);
      end else dest := Self;
      if (dest.FDatabase<>Self.FDatabase) then Raise Exception.Create('Dest database is not the same');
      if (DestOrphan<>Orphan) then Raise Exception.Create(Format('Orphan(%s) and DestOrphan(%s) are the same',[Orphan,DestOrphan]));
      AutomaticMove;
      Result := True;
    finally
      UnlockDatabase;
    end;
  Except
    On E:Exception do begin
      TLog.NewLog(lterror,ClassName,'Error at DoMoveBlockChain: ('+E.ClassName+') '+E.Message);
      Raise;
    end;
  End;
end;

function TSQLiteStorage.DoSaveBank: Boolean;
Var d : TSQLite3Database;
  ms : TMemoryStream;
begin
  Result := False;
  TLog.NewLog(ltInfo,ClassName,'Saving Safebox blocks:'+IntToStr(Bank.BlocksCount)+' Orphan:'+Orphan);
  try
    d := LockDatabase;
    try
      d.BeginTransaction;
      try
        ms := TMemoryStream.Create;
        try
          Bank.SafeBox.SaveSafeBoxToAStream(ms,0,Bank.SafeBox.BlocksCount-1);
          ms.Position := 0;
          InternalSaveSafebox(d,Orphan,Bank.BlocksCount,ms.Memory,ms.Size);
        finally
          ms.Free;
        end;
        d.Commit;
        Result := True;
      Except
        d.Rollback;
        Raise;
      end;
    finally
      UnlockDatabase;
    end;
  Except
    On E:Exception do begin
      TLog.NewLog(lterror,ClassName,Format('Error saving bank %d (%s):%s',[Bank.BlocksCount,E.ClassName,E.Message]));
      Raise;
    end;
  end;
end;

function TSQLiteStorage.DoRestoreBank(max_block : Int64; restoreProgressNotify : TProgressNotify) : Boolean;
var stat : TSQLite3Statement;
  d : TSQLite3Database;
  ms : TMemoryStream;
  lrb : TBlockAccount;
  errors : AnsiString;
  nBlock : Integer;
  nSize : Int64;
begin
  Result := False;
  d := LockDatabase;
  try
    stat := d.Prepare(Format('SELECT %s,%s FROM %s WHERE (%s) AND (%s<=%d) ORDER BY %s DESC LIMIT 1',
      [CT_TblFld_CheckPoint_rawdata,CT_TblFld_CheckPoint_block,
       CT_TblName_CheckPoint,GetOrphanWhere(Orphan),
       CT_TblFld_CheckPoint_block,max_block,CT_TblFld_CheckPoint_block]));
    try
      if stat.Step=SQLITE_ROW then begin
        nBlock := stat.ColumnInt(1);
        ms := TMemoryStream.Create;
        try
          nSize := stat.ColumnBytes(0);
          ms.Write(stat.ColumnBlob(0)^,nSize);
          ms.Position:=0;
          If Not Bank.LoadBankFromStream(ms,False,Nil,Nil,restoreProgressNotify,errors) then begin
            TLog.NewLog(lterror,Classname,Format('Error restoring safebox block:%d error:%s',[nBlock,errors]) );
            Exit;
          end;
          Result := True;
        finally
          ms.Free;
        end;
      end;
    finally
      stat.Free;
    end;
  finally
    UnlockDatabase;
  end;
end;

procedure TSQLiteStorage.DoDeleteBlockChainBlocks(StartingDeleteBlock: Cardinal);
var d : TSQLite3Database;
begin
  d := LockDatabase;
  try
    d.BeginTransaction;
    try
      InternalDeleteBlocks(d,Orphan,StartingDeleteBlock);
      d.Commit;
    Except
      d.Rollback;
      Raise;
    end;
  finally
    UnlockDatabase;
  end;
end;

function TSQLiteStorage.DoBlockExists(Block: Cardinal): Boolean;
var stat : TSQLite3Statement;
begin
  stat := FDatabase.Prepare(Format('SELECT %s FROM %s WHERE (%s) AND (%s=%d)',
    [CT_TblFld_BlockChain_block,
     CT_TblName_BlockChain,
     GetOrphanWhere(Orphan),
     CT_TblFld_BlockChain_block,Block]));
  try
    if (stat.Step=SQLITE_ROW) then begin
      Result := True;
    end else Result := False;
  finally
    stat.Free;
  end;
end;

function TSQLiteStorage.GetFirstBlockNumber: Int64;
var stat : TSQLite3Statement;
begin
  stat := FDatabase.Prepare(Format('SELECT %s FROM %s WHERE (%s) ORDER BY %s LIMIT 1',
    [CT_TblFld_BlockChain_block,
     CT_TblName_BlockChain,
     GetOrphanWhere(Orphan),
     CT_TblFld_BlockChain_block]));
  try
    if (stat.Step=SQLITE_ROW) then begin
      Result := stat.ColumnInt(0);
    end else Result := -1;
  finally
    stat.Free;
  end;
end;

function TSQLiteStorage.GetLastBlockNumber: Int64;
var stat : TSQLite3Statement;
begin
  stat := FDatabase.Prepare(Format('SELECT %s FROM %s WHERE (%s) ORDER BY %s DESC LIMIT 1',
    [CT_TblFld_BlockChain_block,
     CT_TblName_BlockChain,
     GetOrphanWhere(Orphan),
     CT_TblFld_BlockChain_block]));
  try
    if (stat.Step=SQLITE_ROW) then begin
      Result := stat.ColumnInt(0);
    end else Result := -1;
  finally
    stat.Free;
  end;
end;

function TSQLiteStorage.DoInitialize: Boolean;
  procedure GetTalbeNames(sl : TStringList);
  Var sqls : TSQLite3Statement;
  begin
    sl.Clear;
    sqls := FDatabase.Prepare('SELECT name FROM sqlite_master WHERE type=''table''');
    try
      while (sqls.Step = SQLITE_ROW) do begin
        sl.Add(sqls.ColumnText(0));
      end;
    finally
      sqls.Free;
    end;
  end;

var
  sl : TStringList;
  d : TSQLite3Database;
begin
  d := LockDatabase;
  try
    sl := TStringList.Create;
    try
      GetTalbeNames(sl);
      if (sl.IndexOf(CT_TblName_BlockChain)<0) then begin
        InternalExecuteSQL(d,'CREATE TABLE "'+CT_TblName_BlockChain+'" '
          +'(`block` INTEGER NOT NULL, `orphan` TEXT, `timestamp` INTEGER NOT NULL, `target` TEXT NOT NULL, `reward` REAL NOT NULL, `fee` REAL NOT NULL, `operations_count` INTEGER NOT NULL, '
          +'`volume` REAL NOT NULL, `rawpayload` TEXT, `rawdata` BLOB, `accountkey` TEXT, `protocol_version` INTEGER NOT NULL, `protocol_available` INTEGER NOT NULL, `nonce` INTEGER NOT NULL, '
          +'`safe_box_hash` TEXT, `operations_hash` TEXT, `proof_of_work` TEXT);');
        InternalExecuteSQL(d,'CREATE UNIQUE INDEX `tblockchain_block` ON `tblockchain` (`block` ASC,`orphan`);');
      end;
      if (sl.IndexOf(CT_TblName_Accounts)<0) then begin
        InternalExecuteSQL(d,'CREATE TABLE "'+CT_TblName_Accounts+'" '
          +'( `block` INTEGER NOT NULL, `orphan` TEXT, `nopblock` INTEGER NOT NULL, `right_ophash` TEXT NOT NULL, `account` INTEGER NOT NULL, '
          +'`n_operation` INTEGER, `amount` REAL, `hexa_payload` TEXT, `op_text` TEXT, `optype` INTEGER NOT NULL);');
        InternalExecuteSQL(d,'CREATE INDEX `taccounts_account` ON `taccounts` (`block` ASC,`account` ASC,`orphan`);');
        InternalExecuteSQL(d,'CREATE INDEX `taccounts_ophash` ON `taccounts` (`right_ophash`,`orphan`);');
      end;
      if (sl.IndexOf(CT_TblName_CheckPoint)<0) then begin
        InternalExecuteSQL(d,'CREATE TABLE "'+CT_TblName_CheckPoint+'" '
          +'( `idcheckpoint` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, '
          +'`block` INTEGER NOT NULL, `orphan` TEXT, `rawdata` BLOB);');
      end;
      // Pragmas
      sqlite3_busy_timeout(FDatabase.Handle,500);  // 500 ms timeout
    finally
      sl.Free;
    end;
  finally
    UnlockDatabase;
  end;
  Result := True;
end;

function TSQLiteStorage.DoCreateSafeBoxStream(blockCount: Cardinal): TStream;
var d : TSQLite3Database;
  stat : TSQLite3Statement;
begin
  Result := Nil;
  d := LockDatabase;
  try
    stat := d.Prepare(Format('SELECT %s FROM %s WHERE (%s) AND (%s=%d) ORDER BY %s DESC LIMIT 1',
      [CT_TblFld_CheckPoint_rawdata,
       CT_TblName_CheckPoint,GetOrphanWhere(Orphan),
       CT_TblFld_CheckPoint_block,blockCount,CT_TblFld_CheckPoint_block]));
    try
      if stat.Step=SQLITE_ROW then begin
        Result := TMemoryStream.Create;
        try
          Result.Write(stat.ColumnBlob(0)^,stat.ColumnBytes(0));
          Result.Position:=0;
        Except
          FreeAndNil(Result);
          Raise;
        end;
      end;
    finally
      stat.Free;
    end;
  finally
    UnlockDatabase;
  end;
end;

procedure TSQLiteStorage.DoEraseStorage;
var d : TSQLite3Database;
begin
  d := LockDatabase;
  try
    d.BeginTransaction;
    try
      InternalExecuteSQL(d,Format('DELETE FROM %s',[CT_TblName_BlockChain]));
      InternalExecuteSQL(d,Format('DELETE FROM %s',[CT_TblName_Accounts]));
      InternalExecuteSQL(d,Format('DELETE FROM %s',[CT_TblName_CheckPoint]));
      d.Commit;
    except
      d.Rollback;
      Raise;
    end;
  finally
    UnlockDatabase;
  end;
end;

procedure TSQLiteStorage.DoSavePendingBufferOperations(OperationsHashTree: TOperationsHashTree);
var d : TSQLite3Database;
  stat : TSQLite3Statement;
  ms : TMemoryStream;
begin
  try
    d := LockDatabase;
    try
      d.BeginTransaction;
      try
        InternalExecuteSQL(d,Format('DELETE FROM %s WHERE (%s)',
         [CT_TblName_BlockChain,GetOrphanWhere('PENDING')]));
        stat := d.Prepare(Format('INSERT INTO %s (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
          [CT_TblName_BlockChain,
           //
           CT_TblFld_BlockChain_block,CT_TblFld_BlockChain_accountkey,CT_TblFld_BlockChain_reward,
           CT_TblFld_BlockChain_fee,CT_TblFld_BlockChain_protocol_version,CT_TblFld_BlockChain_protocol_available,
           CT_TblFld_BlockChain_timestamp,CT_TblFld_BlockChain_target,CT_TblFld_BlockChain_nonce,
           CT_TblFld_BlockChain_rawpayload,CT_TblFld_BlockChain_safe_box_hash,CT_TblFld_BlockChain_operations_hash,
           CT_TblFld_BlockChain_proof_of_work,CT_TblFld_BlockChain_orphan,CT_TblFld_BlockChain_operations_count,
           CT_TblFld_BlockChain_volume,CT_TblFld_BlockChain_rawdata]));
        try
          stat.BindInt(1,0);
          stat.BindText(2,'PENDING');
          stat.BindInt(3,0);
          stat.BindInt(4,0);
          stat.BindInt(5,0);
          stat.BindInt(6,0);
          stat.BindInt(7,0);
          stat.BindText(8,'PENDING');
          stat.BindInt(9,0);
          stat.BindText(10,'PENDING');
          stat.BindText(11,'PENDING');
          stat.BindText(12,'PENDING');
          stat.BindText(13,'PENDING');
          stat.BindText(14,'PENDING');
          stat.BindInt(15,OperationsHashTree.OperationsCount);
          stat.BindDouble(16,RoundTo((OperationsHashTree.TotalAmount+OperationsHashTree.TotalFee) / 10000,-4));
          ms := TMemoryStream.Create;
          try
            OperationsHashTree.SaveOperationsHashTreeToStream(ms,False);
            stat.BindBlob(17,ms.Memory,ms.Size);
          finally
            ms.Free;
          end;
          stat.StepAndReset;
        finally
          stat.Free;
        end;
        d.Commit;
      except
        d.Rollback;
        Raise;
      end;
    finally
      UnlockDatabase;
    end;
  except
    On E:Exception do begin
      TLog.NewLog(lterror,ClassName,Format('Error saving %d pending operations (%s):%s',[OperationsHashTree.OperationsCount,E.ClassName,E.Message]));
      Raise;
    end;
  end;
end;

procedure TSQLiteStorage.DoLoadPendingBufferOperations(OperationsHashTree: TOperationsHashTree);
var d : TSQLite3Database;
  stat : TSQLite3Statement;
  ms : TMemoryStream;
  errors : AnsiString;
begin
  errors := '';
  try
    d := LockDatabase;
    try
      stat := d.Prepare(Format('SELECT %s FROM %s WHERE %s',
        [CT_TblFld_BlockChain_rawdata, CT_TblName_BlockChain,GetOrphanWhere('PENDING')]));
      try
        if (stat.Step=SQLITE_ROW) then begin
          ms := TMemoryStream.Create;
          try
            ms.Write(stat.ColumnBlob(0)^,stat.ColumnBytes(0));
            ms.Position:=0;
            OperationsHashTree.LoadOperationsHashTreeFromStream(ms,false,CT_PROTOCOL_3,Nil,errors);
          finally
            ms.Free;
          end;
        end;
      finally
        stat.Free;
      end;
    finally
      UnlockDatabase;
    end;
  except
    On E:Exception do begin
      TLog.NewLog(lterror,ClassName,Format('Error loading pending operations (%s):%s',[E.ClassName,E.Message]));
      Raise;
    end;
  end;
end;

constructor TSQLiteStorage.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FIsCopiedDatabase:=False;
  FDatabase := Nil;
  FSQLiteFileName:='';
  FStorageLock := TPCCriticalSection.Create(ClassName);
end;

destructor TSQLiteStorage.Destroy;
begin
  If Not FIsCopiedDatabase then begin
    FreeAndNil(FStorageLock);
    FreeAndNil(FDatabase);
  end;
  inherited Destroy;
end;

procedure TSQLiteStorage.CopyConfiguration(const CopyFrom: TStorage);
begin
  If CopyFrom=Self then Raise Exception.Create('ERROR DEV 20180514-1');
  inherited CopyConfiguration(CopyFrom);
  if (FIsCopiedDatabase) then Raise Exception.Create('Is copied database');
  if Not (CopyFrom is TSQLiteStorage) then Raise Exception.Create('Must be a '+ClassName);
  // Will use SAME database file
  FIsCopiedDatabase := True;
  FreeAndNil(FStorageLock);
  FreeAndNil(FDatabase);
  FStorageLock := TSQLiteStorage(CopyFrom).FStorageLock;
  CopyFrom.Initialize;
  FDatabase := TSQLiteStorage(CopyFrom).FDatabase;
end;

function TSQLiteStorage.HasUpgradedToVersion2: Boolean;
begin
  Result := True;
end;

procedure TSQLiteStorage.CleanupVersion1Data;
begin
  //
end;

initialization
  TSQLiteStorage.SQLiteFormatSettings.CurrencyDecimals:=4;
  TSQLiteStorage.SQLiteFormatSettings.ThousandSeparator:=',';
  TSQLiteStorage.SQLiteFormatSettings.DecimalSeparator:='.';
  TSQLiteStorage.SQLiteFormatSettings.DateSeparator:='-';
  TSQLiteStorage.SQLiteFormatSettings.TimeSeparator:=':';
  TSQLiteStorage.SQLiteFormatSettings.ShortDateFormat:='yyyy-mm-dd';
  TSQLiteStorage.SQLiteFormatSettings.LongDateFormat:='yyyy-mm-dd';
  TSQLiteStorage.SQLiteFormatSettings.ShortTimeFormat:='hh:mm:ss';
  TSQLiteStorage.SQLiteFormatSettings.LongTimeFormat:='hh:mm:ss';
end.

