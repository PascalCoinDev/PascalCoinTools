unit UFRMBlockChainFileUtils;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

uses
{$IFnDEF FPC}
  Windows,
{$ELSE}
  LCLIntf, LCLType, LMessages,
{$ENDIF}
  Messages, SysUtils, Variants, Classes, Graphics,
  UCrypto, UOpenSSL, UOpenSSLdef,
  Controls, Forms, Dialogs, StdCtrls, Buttons, ComCtrls, ExtCtrls,
  UExportTo;

type

  { TFRMBlockChainFileUtils }

  TFRMBlockChainFileUtils = class(TForm)
    bbSelFile: TButton;
    bbShowBlocksInfo: TButton;
    bbExportToSQLite: TButton;
    memoFileInfo: TMemo;
    FileOpenDialog: TOpenDialog;
    ebFileName: TEdit;
    Label1: TLabel;
    ebNewBlockStart: TEdit;
    Label2: TLabel;
    ebNewBlockEnd: TEdit;
    bbExportToFile: TBitBtn;
    PageControl: TPageControl;
    pnlBottom: TPanel;
    pnlTop: TPanel;
    SaveDialog: TSaveDialog;
    ProgressBar: TProgressBar;
    tsInfo: TTabSheet;
    tsExportBlockchainFile: TTabSheet;
    ProgressBarSQLite: TProgressBar;
    lblSaveNewFileProgress: TLabel;
    lblExportToSQLiteProgress: TLabel;
    procedure bbSelFileClick(Sender: TObject);
    procedure bbShowBlocksInfoClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure bbExportToFileClick(Sender: TObject);
    procedure bbExportToSQLiteClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    { Private declarations }
    FProcessing : Boolean;
    FCancelProcess : Boolean;
    FExportToSQLiteThread : TExportToSQLiteThread;
    FExportToFileThread : TExportToNewFileThread;
    Procedure LoadFile(filename : String);
    procedure OnExportToSQLiteThreadNotify(Sender : TObject);
    procedure OnExportToSQLiteTerminated(Sender : TObject);
    procedure OnExportToFileThreadNotify(Sender : TObject);
    procedure OnExportToFileTerminated(Sender : TObject);
    procedure ShowExportThreadProgress(AExportThread : TExportTo; AProgressBar : TProgressBar; ALabel : TLabel);
  public
    { Public declarations }
  end;

var
  FRMBlockChainFileUtils: TFRMBlockChainFileUtils;

implementation

uses UAccounts, UBlockChain, UFileStorage, UChunk, UBaseTypes;

{$IFnDEF FPC}
  {$R *.dfm}
{$ELSE}
  {$R *.lfm}
{$ENDIF}

procedure TFRMBlockChainFileUtils.bbExportToSQLiteClick(Sender: TObject);
var Ln_start,Ln_end : Integer;
  LDestFN : String;
begin
  if Assigned(FExportToSQLiteThread) then begin
    FExportToSQLiteThread.Terminate;
    Exit;
  end;
  Ln_start := StrToIntDef(ebNewBlockStart.Text,-1);
  Ln_end := StrToIntDef(ebNewBlockEnd.Text,-1);
  if Not SaveDialog.Execute then exit;
  LDestFN := SaveDialog.FileName;
  ProgressBarSQLite.Max := MaxInt;
  ProgressBarSQLite.Min := Ln_start;
  ProgressBarSQLite.Max := Ln_end;
  ProgressBarSQLite.Position := Ln_start;
  ProgressBarSQLite.Visible := True;
  bbExportToSQLite.Caption := 'Exporting to SQLite...';
  FExportToSQLiteThread := TExportToSQLiteThread.Create(ebFileName.Text,LDestFN,Ln_start,Ln_end,OnExportToSQLiteThreadNotify,OnExportToSQLiteTerminated);
end;

procedure TFRMBlockChainFileUtils.bbExportToFileClick(Sender: TObject);
var Ln_start,Ln_end : Integer;
  LDestFN : String;
begin
  if Assigned(FExportToFileThread) then begin
    FExportToFileThread.Terminate;
    Exit;
  end;
  Ln_start := StrToIntDef(ebNewBlockStart.Text,-1);
  Ln_end := StrToIntDef(ebNewBlockEnd.Text,-1);
  if Not SaveDialog.Execute then exit;
  LDestFN := SaveDialog.FileName;
  ProgressBar.Max := MaxInt;
  ProgressBar.Min := Ln_start;
  ProgressBar.Max := Ln_end;
  ProgressBar.Position := Ln_start;
  ProgressBar.Visible := True;
  bbExportToFile.Caption := 'Exporting to File...';
  FExportToFileThread := TExportToNewFileThread.Create(ebFileName.Text,LDestFN,Ln_start,Ln_end,OnExportToFileThreadNotify,OnExportToFileTerminated);
end;

procedure TFRMBlockChainFileUtils.bbSelFileClick(Sender: TObject);
begin
  if Not FileOpenDialog.Execute then exit;
  LoadFile( FileOpenDialog.FileName );
end;

procedure TFRMBlockChainFileUtils.bbShowBlocksInfoClick(Sender: TObject);
Var i : Integer;
  source : TFileStorage;
  ops : TPCOperationsComp;
  tc : TTickCount;
begin
  if FProcessing then begin
    FCancelProcess := True;
    Exit;
  end;
  tc := TPlatform.GetTickCount;
  source := TFileStorage.Create(Nil);
  Try
    FCancelProcess := False;
    FProcessing := True;
    bbShowBlocksInfo.Caption := 'Stop...';
    source.SetBlockChainFile(ebFileName.Text);
    source.ReadOnly := true;
    If not source.Initialize then raise Exception.Create('Cannot initialize source');
    ops := TPCOperationsComp.Create(Nil);
    Try
      Try
        i := source.FirstBlock;
        for i:=source.FirstBlock to source.LastBlock do begin
          if FCancelProcess then Exit;

          If Not source.LoadBlockChainBlock(ops,i) then begin
            memoFileInfo.Lines.Add(Format('Cannot load source block %d',[i]));
          end else begin
            memoFileInfo.Lines.Add(Format('%d Ops:%d %s',[i,ops.Count,TPCOperationsComp.OperationBlockToText(ops.OperationBlock)]));
          end;
          if (TPlatform.GetElapsedMilliseconds(tc)>500) then begin
            tc := TPlatform.GetTickCount;
            Application.ProcessMessages;
          end;
        end;
      Finally
      End;
    Finally
      ops.Free;
    End;
  Finally
    source.Free;
    FProcessing := False;
    bbShowBlocksInfo.Caption := 'Show blocks Info';
  End;
end;

procedure TFRMBlockChainFileUtils.FormCreate(Sender: TObject);
begin
  FCancelProcess := false;
  FProcessing := false;
  memoFileInfo.Clear;
  ebFileName.Text := ''; ebNewBlockStart.Text := ''; ebNewBlockEnd.Text := '';
  ProgressBar.Visible := false;
  ProgressBar.Min :=0;
  ProgressBar.Max := MaxInt;
  TCrypto.InitCrypto;
  FExportToSQLiteThread := Nil;
  ProgressBarSQLite.Visible := false;
  bbExportToSQLite.Caption := 'Export blockchain to SQLite';
  bbExportToFile.Caption :=  'Export blockchain to File';
  lblExportToSQLiteProgress.Caption := '';
  lblSaveNewFileProgress.Caption := '';
end;

procedure TFRMBlockChainFileUtils.FormDestroy(Sender: TObject);
begin
  If Assigned(FExportToSQLiteThread) then begin
    FExportToSQLiteThread.Terminate;
    FExportToSQLiteThread.WaitFor;
  end;
  If Assigned(FExportToFileThread) then begin
    FExportToFileThread.Terminate;
    FExportToFileThread.WaitFor;
  end;
end;

procedure TFRMBlockChainFileUtils.LoadFile(filename: String);
Var
  fs : TFileStorage;
  errors : String;
  i : Integer;
  not_start,not_found_total : Integer;
begin
  ebFileName.Text := filename;
  ebNewBlockStart.Text := '';
  ebNewBlockEnd.Text:='';
  fs := TFileStorage.Create(Nil);
  Try
    fs.SetBlockChainFile(filename);
    fs.ReadOnly := true;
    memoFileInfo.Lines.Add('File: '+filename);
    If fs.Initialize then begin
      memoFileInfo.Lines.Add(Format('first:%d last:%d total:%d',[fs.FirstBlock,fs.LastBlock,fs.LastBlock-fs.FirstBlock+1]));
      ebNewBlockStart.Text := Inttostr(fs.FirstBlock);
      ebNewBlockEnd.Text := Inttostr(fs.LastBlock);
      not_start := -1;
      not_found_total := 0;
      for i:=fs.FirstBlock to fs.LastBlock do begin
        if not fs.BlockExists(i) then begin
          if not_start<0 then not_start:=i;
          inc(not_found_total);
        end else begin
          if not_start>=0 then begin
            memoFileInfo.Lines.Add(Format('Blocks from %d to %d (%d) not found',[not_start,i-1,i-not_start]));
            not_start := -1;
          end;
        end;
      end;
      memoFileInfo.Lines.Add(Format('FINAL first:%d last:%d not_found:%d total:%d',[fs.FirstBlock,fs.LastBlock,not_found_total,fs.LastBlock-fs.FirstBlock+1-not_found_total]));
    end else memoFileInfo.Lines.Add(Format('Errors:%s',[errors]));
  Finally
    fs.Free;
  End;
end;

procedure TFRMBlockChainFileUtils.OnExportToFileTerminated(Sender: TObject);
begin
  OnExportToFileThreadNotify(Sender);
  ProgressBar.Visible := False;
  lblSaveNewFileProgress.Caption := FExportToFileThread.LastError;
  memoFileInfo.Lines.Add(Format('Exported %d blocks and %d Operations to SQLite file %s',
    [TExportTo(FExportToFileThread).SavedCount,TExportTo(FExportToFileThread).OperationsSavedCount,
     TExportToSQLiteThread(FExportToFileThread).DestSQLiteFile]));
  FExportToFileThread := Nil;
  bbExportToFile.Caption := 'Export blockchain to File';
end;

procedure TFRMBlockChainFileUtils.OnExportToFileThreadNotify(Sender: TObject);
begin
  ShowExportThreadProgress(TExportTo(Sender),ProgressBar,lblSaveNewFileProgress);
end;

procedure TFRMBlockChainFileUtils.OnExportToSQLiteTerminated(Sender: TObject);
begin
  OnExportToSQLiteThreadNotify(Sender);
  ProgressBarSQLite.Visible := False;
  lblExportToSQLiteProgress.Caption := FExportToSQLiteThread.LastError;
  memoFileInfo.Lines.Add(Format('Exported %d blocks and %d Operations to SQLite file %s',
    [TExportTo(FExportToSQLiteThread).SavedCount,TExportTo(FExportToSQLiteThread).OperationsSavedCount,
     TExportToSQLiteThread(FExportToSQLiteThread).DestSQLiteFile]));
  FExportToSQLiteThread := Nil;
  bbExportToSQLite.Caption := 'Export blockchain to SQLite';
end;

procedure TFRMBlockChainFileUtils.OnExportToSQLiteThreadNotify(Sender: TObject);
begin
  ShowExportThreadProgress(TExportTo(Sender),ProgressBarSQLite,lblExportToSQLiteProgress);
end;

procedure TFRMBlockChainFileUtils.ShowExportThreadProgress(
  AExportThread: TExportTo; AProgressBar: TProgressBar; ALabel: TLabel);
var Lsprogress : String;
begin
  if (AExportThread.EndPos-AExportThread.StartPos)>0 then begin
    Lsprogress := FormatFloat('0.0',((AExportThread.CurrentPos - AExportThread.StartPos)*100) / (AExportThread.EndPos-AExportThread.StartPos))+'%';
  end else Lsprogress := '';
  AProgressBar.Position := AExportThread.CurrentPos;
  ALabel.Caption := Format('Exporting %d/%d %s Blocks:%d Operations:%d',
    [AExportThread.CurrentPos,AExportThread.EndPos, Lsprogress, AExportThread.SavedCount,AExportThread.OperationsSavedCount]) ;
end;

end.
