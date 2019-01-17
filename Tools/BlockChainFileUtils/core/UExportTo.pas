unit UExportTo;

{$IFDEF FPC}
{$mode delphi}
{$ENDIF}

interface

uses
  Classes, SysUtils, UThread, UBlockChain, UFileStorage, USQLiteStorage, UBaseTypes{$IFDEF FPC}, sqlite3conn{$ENDIF};

type


  TExportTo = Class(TPCThread)
  private
  protected
    FStartPos: Integer;
    FEndPos: Integer;
    FCurrentPos: Integer;
    FLastError: String;
    FSavedCount: Integer;
    FOnNotify: TNotifyEvent;
    FOperationsSavedCount: Integer;
    //
    function GetSourceAndDest(var ASource, ADest : TStorage) : Boolean; virtual; abstract;
    procedure BCExecute; override;
  public
    Constructor Create(AStartPos, AEndPos : Integer; AOnNotify, AOnTerminate : TNotifyEvent);
    property StartPos : Integer read FStartPos;
    property EndPos : Integer read FEndPos;
    property CurrentPos : Integer read FCurrentPos;
    property SavedCount : Integer read FSavedCount;
    property OperationsSavedCount : Integer read FOperationsSavedCount;
    property LastError : String read FLastError;
    property OnNotify : TNotifyEvent read FOnNotify write FOnNotify;
  end;


  { TExportToSQLiteThread }

  TExportToSQLiteThread = Class(TExportTo)
  private
    FDestSQLiteFile: string;
    FSourceBlockchainFile: String;
  protected
    function GetSourceAndDest(var ASource, ADest : TStorage) : Boolean; override;
  public
    Constructor Create(Const ASourceBlockchainFile, ADestSQLiteFile : String; AStartPos, AEndPos : Integer; AOnNotify, AOnTerminate : TNotifyEvent);
    property SourceBlockchainFile: String read FSourceBlockchainFile;
    property DestSQLiteFile: string read FDestSQLiteFile;
  end;

  { TExportToNewFileThread }

  TExportToNewFileThread = Class(TExportTo)
  private
    FDestBlockchainFile: string;
    FSourceBlockchainFile: String;
  protected
    function GetSourceAndDest(var ASource, ADest : TStorage) : Boolean; override;
  public
    Constructor Create(Const ASourceBlockchainFile, ADestBlockchainFile : String; AStartPos, AEndPos : Integer; AOnNotify, AOnTerminate : TNotifyEvent);
    property SourceBlockchainFile: String read FSourceBlockchainFile;
    property DestBlockchainFile: string read FDestBlockchainFile;
  end;


implementation

{ TExportTo }

procedure TExportTo.BCExecute;
var LSource : TStorage;
  LDest : TStorage;
  LTempOpComp : TPCOperationsComp;
  LLastTC : TTickCount;
begin
  LLastTC := TPlatform.GetTickCount;
  LSource := Nil;
  LDest := Nil;
  Try
    if Not GetSourceAndDest(LSource,LDest) then begin
      FLastError := 'Source or Dest not valid';
      Exit;
    end;
    LTempOpComp := TPCOperationsComp.Create(Nil);
    Try
      while (FCurrentPos<FEndPos) and (Not Terminated) do begin
        if LSource.LoadBlockChainBlock(LTempOpComp,FCurrentPos) then begin
          LDest.SaveBlockChainBlock(LTempOpComp);
          inc(FSavedCount);
          inc(FOperationsSavedCount,LTempOpComp.Count);
        end;
        inc(FCurrentPos);
        if (Assigned(FOnNotify)) And (TPlatform.GetElapsedMilliseconds(LLastTC)>500) then begin
          LLastTC := TPlatform.GetTickCount;
          FOnNotify(Self);
        end;
      end;
    Finally
      LTempOpComp.Free;
    End;
  finally
    FreeAndNil(LSource);
    FreeAndNil(LDest);
  end;
end;

constructor TExportTo.Create(AStartPos, AEndPos: Integer; AOnNotify, AOnTerminate: TNotifyEvent);
begin
  FStartPos := AStartPos;
  FEndPos:= AEndPos;
  FCurrentPos:= AStartPos;
  FLastError := '';
  FSavedCount:= 0;
  FOperationsSavedCount := 0;
  FOnNotify := AOnNotify;
  Inherited Create(True);
  FreeOnTerminate := True;
  OnTerminate := AOnTerminate;
  Suspended := False;
end;

{ TExportToSQLiteThread }

constructor TExportToSQLiteThread.Create(const ASourceBlockchainFile, ADestSQLiteFile: String; AStartPos, AEndPos: Integer; AOnNotify, AOnTerminate : TNotifyEvent);
begin
  FDestSQLiteFile := ADestSQLiteFile;
  FSourceBlockchainFile := ASourceBlockchainFile;
  inherited Create(AStartPos,AEndPos,AOnNotify,AOnTerminate);
end;

function TExportToSQLiteThread.GetSourceAndDest(var ASource, ADest: TStorage): Boolean;
begin
  Result := False;

  FreeAndNil(ASource);
  FreeAndNil(ADest);

  ASource := TFileStorage.Create(Nil);
  ASource.ReadOnly := true;
  TFileStorage(ASource).SetBlockChainFile(FSourceBlockchainFile);
  ASource.ReadOnly := true;
  If not ASource.Initialize then begin
    FLastError := 'Source file cannot be initialized: '+FSourceBlockchainFile;
    Exit;
  end;

  ADest := TSQLiteStorage.Create(Nil);
  ADest.ReadOnly := False;
  TSQLiteStorage(ADest).SQLiteFileName:=FDestSQLiteFile;
  If not ADest.Initialize then begin
    FLastError := 'Dest SQLite file cannot be initialized: '+FDestSQLiteFile;
    Exit;
  end;

  Result := True;
end;

{ TExportToNewFileThread }

constructor TExportToNewFileThread.Create(const ASourceBlockchainFile,
  ADestBlockchainFile: String; AStartPos, AEndPos: Integer; AOnNotify,
  AOnTerminate: TNotifyEvent);
begin
  FSourceBlockchainFile := ASourceBlockchainFile;
  FDestBlockchainFile := ADestBlockchainFile;
  inherited Create(AStartPos,AEndPos,AOnNotify,AOnTerminate);
end;

function TExportToNewFileThread.GetSourceAndDest(var ASource, ADest: TStorage): Boolean;
begin
  Result := False;

  FreeAndNil(ASource);
  FreeAndNil(ADest);

  ASource := TFileStorage.Create(Nil);
  ASource.ReadOnly := true;
  TFileStorage(ASource).SetBlockChainFile(FSourceBlockchainFile);
  ASource.ReadOnly := true;
  If not ASource.Initialize then begin
    FLastError := 'Source file cannot be initialized: '+FSourceBlockchainFile;
    Exit;
  end;

  ADest := TFileStorage.Create(Nil);
  ADest.ReadOnly := False;
  TFileStorage(ADest).SetBlockChainFile(FDestBlockchainFile);
  If not ADest.Initialize then begin
    FLastError := 'Dest file cannot be initialized: '+FDestBlockchainFile;
    Exit;
  end;

  Result := True;
end;

end.
