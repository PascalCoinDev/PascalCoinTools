program FMXPascalCoinKeyTool;

uses
  System.StartUpCopy,
  FMX.Forms,
  fmxMainForm in '..\..\src\Forms\FMX\fmxMainForm.pas' {Form1},
  uPascalCoinKeyTool in '..\..\src\Core\uPascalCoinKeyTool.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
