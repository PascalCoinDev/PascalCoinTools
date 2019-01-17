object FRMBlockChainFileUtils: TFRMBlockChainFileUtils
  Left = 588
  Top = 288
  Caption = 'PascalCoin BlockChain File Utils'
  ClientHeight = 487
  ClientWidth = 697
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = True
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object pnlTop: TPanel
    Left = 0
    Top = 0
    Width = 697
    Height = 201
    Align = alTop
    BevelOuter = bvNone
    TabOrder = 0
    object bbSelFile: TButton
      Left = 8
      Top = 15
      Width = 145
      Height = 25
      Caption = 'Select blockchain File'
      TabOrder = 0
      OnClick = bbSelFileClick
    end
    object ebFileName: TEdit
      Left = 165
      Top = 15
      Width = 521
      Height = 21
      ReadOnly = True
      TabOrder = 1
    end
    object PageControl: TPageControl
      Left = 8
      Top = 46
      Width = 678
      Height = 150
      ActivePage = tsExportBlockchainFile
      TabOrder = 2
      object tsInfo: TTabSheet
        Caption = 'Information'
        object bbShowBlocksInfo: TButton
          Left = 15
          Top = 14
          Width = 225
          Height = 25
          Caption = 'Show blocks Info'
          TabOrder = 0
          OnClick = bbShowBlocksInfoClick
        end
      end
      object tsExportBlockchainFile: TTabSheet
        Caption = 'Export Blockchain file'
        object Label1: TLabel
          Left = 8
          Top = 23
          Width = 78
          Height = 13
          Caption = 'New block start:'
          Color = clBtnFace
          ParentColor = False
          Transparent = False
        end
        object Label2: TLabel
          Left = 188
          Top = 21
          Width = 73
          Height = 13
          Caption = 'New block end:'
          Color = clBtnFace
          ParentColor = False
          Transparent = False
        end
        object lblSaveNewFileProgress: TLabel
          Left = 380
          Top = 60
          Width = 117
          Height = 13
          Caption = 'Save/Export Progress...'
          Color = clBtnFace
          ParentColor = False
        end
        object lblExportToSQLiteProgress: TLabel
          Left = 380
          Top = 92
          Width = 117
          Height = 13
          Caption = 'Save/Export Progress...'
          Color = clBtnFace
          ParentColor = False
        end
        object ebNewBlockStart: TEdit
          Left = 98
          Top = 18
          Width = 66
          Height = 21
          TabOrder = 0
        end
        object ebNewBlockEnd: TEdit
          Left = 283
          Top = 18
          Width = 66
          Height = 21
          TabOrder = 1
        end
        object bbExportToFile: TBitBtn
          Left = 8
          Top = 55
          Width = 244
          Height = 25
          Caption = 'Save new file'
          Glyph.Data = {
            36030000424D3603000000000000360000002800000010000000100000000100
            18000000000000030000120B0000120B00000000000000000000FF00FFFF00FF
            FF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00
            FFFF00FFFF00FFFF00FFFF00FFFF00FF97433F97433FB59A9BB59A9BB59A9BB5
            9A9BB59A9BB59A9BB59A9B93303097433FFF00FFFF00FFFF00FFFF00FF97433F
            D66868C66060E5DEDF92292A92292AE4E7E7E0E3E6D9DFE0CCC9CC8F201FAF46
            4697433FFF00FFFF00FFFF00FF97433FD06566C25F5FE9E2E292292A92292AE2
            E1E3E2E6E8DDE2E4CFCCCF8F2222AD464697433FFF00FFFF00FFFF00FF97433F
            D06565C15D5DECE4E492292A92292ADFDDDFE1E6E8E0E5E7D3D0D28A1E1EAB44
            4497433FFF00FFFF00FFFF00FF97433FD06565C15B5CEFE6E6EDE5E5E5DEDFE0
            DDDFDFE0E2E0E1E3D6D0D2962A2AB24A4A97433FFF00FFFF00FFFF00FF97433F
            CD6263C86060C96767CC7272CA7271C66969C46464CC6D6CCA6667C55D5DCD65
            6597433FFF00FFFF00FFFF00FF97433FB65553C27B78D39D9CD7A7A5D8A7A6D8
            A6A5D7A09FD5A09FD7A9A7D8ABABCC666797433FFF00FFFF00FFFF00FF97433F
            CC6667F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9CC66
            6797433FFF00FFFF00FFFF00FF97433FCC6667F9F9F9F9F9F9F9F9F9F9F9F9F9
            F9F9F9F9F9F9F9F9F9F9F9F9F9F9CC666797433FFF00FFFF00FFFF00FF97433F
            CC6667F9F9F9CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDF9F9F9CC66
            6797433FFF00FFFF00FFFF00FF97433FCC6667F9F9F9F9F9F9F9F9F9F9F9F9F9
            F9F9F9F9F9F9F9F9F9F9F9F9F9F9CC666797433FFF00FFFF00FFFF00FF97433F
            CC6667F9F9F9CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDF9F9F9CC66
            6797433FFF00FFFF00FFFF00FF97433FCC6667F9F9F9F9F9F9F9F9F9F9F9F9F9
            F9F9F9F9F9F9F9F9F9F9F9F9F9F9CC666797433FFF00FFFF00FFFF00FFFF00FF
            97433FF9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F9F99743
            3FFF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF
            00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00FFFF00FF}
          TabOrder = 2
          OnClick = bbExportToFileClick
        end
        object ProgressBar: TProgressBar
          Left = 258
          Top = 55
          Width = 116
          Height = 25
          Max = 440000
          Position = 440000
          TabOrder = 3
        end
        object bbExportToSQLite: TButton
          Left = 8
          Top = 86
          Width = 244
          Height = 25
          Caption = 'Export Blockchain To SQLite'
          TabOrder = 4
          OnClick = bbExportToSQLiteClick
        end
        object ProgressBarSQLite: TProgressBar
          Left = 258
          Top = 86
          Width = 116
          Height = 25
          Max = 440000
          Position = 440000
          TabOrder = 5
        end
      end
    end
  end
  object pnlBottom: TPanel
    Left = 0
    Top = 201
    Width = 697
    Height = 286
    Align = alClient
    BevelOuter = bvNone
    TabOrder = 1
    object memoFileInfo: TMemo
      Left = 0
      Top = 0
      Width = 697
      Height = 286
      Align = alClient
      Lines.Strings = (
        'memoFileInfo')
      ReadOnly = True
      ScrollBars = ssBoth
      TabOrder = 0
    end
  end
  object FileOpenDialog: TOpenDialog
    Options = []
    Left = 340
    Top = 20
  end
  object SaveDialog: TSaveDialog
    Left = 525
    Top = 295
  end
end
