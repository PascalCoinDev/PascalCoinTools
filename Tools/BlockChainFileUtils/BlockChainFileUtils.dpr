program BlockChainFileUtils;

uses
  Forms, {$IFDEF FPC}Interfaces,{$ENDIF}
  UFRMBlockChainFileUtils in 'Gui\UFRMBlockChainFileUtils.pas',
  UExportTo in 'core\UExportTo.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TFRMBlockChainFileUtils, FRMBlockChainFileUtils);
  Application.Run;
end.
