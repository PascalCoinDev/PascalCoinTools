program FMXPascalCoinKeyTool;

uses
  System.StartUpCopy,
  FMX.Forms,
  fmxMainForm in '..\..\src\Forms\FMX\fmxMainForm.pas' {MainForm},
  uPascalCoinKeyTool in '..\..\src\Core\uPascalCoinKeyTool.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
