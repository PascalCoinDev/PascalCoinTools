unit uPascalCoinKeyTool;

{$IFDEF FPC}
{$MODE DELPHI}
{$NOTES OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  Classes,
  SysUtils,
  TypInfo,
  ClpIMac,
  ClpIDigest,
  ClpIECDsaSigner,
  ClpIIESCipher,
  ClpIAesEngine,
  ClpISecureRandom,
  ClpIBufferedCipher,
  ClpIECInterface,
  ClpIParametersWithIV,
  ClpIX9ECParameters,
  ClpIPascalCoinIESEngine,
  ClpIParametersWithRandom,
  ClpIZeroBytePadding,
  ClpIBufferedBlockCipher,
  ClpICbcBlockCipher,
  ClpIECDHBasicAgreement,
  ClpIECDomainParameters,
  ClpIECPublicKeyParameters,
  ClpIECKeyGenerationParameters,
  ClpIECPrivateKeyParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIIESWithCipherParameters,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIPascalCoinECIESKdfBytesGenerator,
  ClpBits,
  ClpHex,
  ClpBase58,
  ClpIESCipher,
  ClpECDsaSigner,
  ClpBigInteger,
  ClpArrayUtils,
  ClpConverters,
  ClpAesEngine,
  ClpCryptoLibTypes,
  ClpCbcBlockCipher,
  ClpSecureRandom,
  ClpCustomNamedCurves,
  ClpMacUtilities,
  ClpCipherUtilities,
  ClpDigestUtilities,
  ClpZeroBytePadding,
  ClpParameterUtilities,
  ClpECDHBasicAgreement,
  ClpParametersWithIV,
  ClpECDomainParameters,
  ClpGeneratorUtilities,
  ClpPascalCoinIESEngine,
  ClpParametersWithRandom,
  ClpECPublicKeyParameters,
  ClpECPrivateKeyParameters,
  ClpIESWithCipherParameters,
  ClpPaddedBufferedBlockCipher,
  ClpECKeyGenerationParameters,
  ClpPascalCoinECIESKdfBytesGenerator;

resourcestring
  SInvalidKeyType = 'Invalid KeyType "%d".';
  SInvalidKeyTypeSelected = 'Invalid KeyType Selected "%d".';
  SInvalidSign = 'Invalid Sign "%d".';

type
  {$SCOPEDENUMS ON}
  TKeyType = (SECP256K1, SECP384R1, SECP521R1, SECT283K1);
  {$SCOPEDENUMS OFF}

type

  { TPascalCoinKeyTool }

  TPascalCoinKeyTool = class sealed(TObject)

  strict private

  const
    PKCS5_SALT_LEN = Int32(8);
    SALT_MAGIC_LEN = Int32(8);
    SALT_SIZE = Int32(8);
    SALT_MAGIC: string = 'Salted__';

    class var
    FRandom: ISecureRandom;

    class function GetSignAsString(ASign: Int32): string; static; inline;
    class function DoECDSASign(const APrivateKey: IECPrivateKeyParameters; const AMessage: TBytes): TCryptoLibGenericArray<TBigInteger>; static;
    class function DoECDSAVerify(const APublicKey: IECPublicKeyParameters; const AMessage: TBytes; const ASig: TCryptoLibGenericArray<TBigInteger>): boolean; static;
    class function RetrieveKeyTypeInt32FromByteArray(const AInput: TBytes; AOffset: Int32): Int32; static; inline;
    class function RetrieveKeyType(AValue: Int32): TKeyType; static; inline;
    class function GetPublicKeyType(const APascalCoinBase58PublicKey: string): TKeyType; static;
    class function GetPrivateKeyType(const AEncryptedPascalCoinPrivateKey, APassword: string): TKeyType; static;
    class function ValidatePascalCoinBase58PublicKeyChecksum(const APascalCoinBase58PublicKey: string): boolean; static;
    class function ValidatePublicKeyHeader(AKeyType: TKeyType; const AInput: TBytes; out AErrorMessage: string): boolean; static;
    class function ValidatePrivateKeyHeader(AKeyType: TKeyType; const AInput: TBytes; out AErrorMessage: string): boolean; static;
    class function IsValidHexString(const AInput: string): boolean; static; inline;
    class function GetIESCipherParameters: IIESWithCipherParameters; static;
    class function GetECIESPascalCoinCompatibilityEngine(): IPascalCoinIESEngine; static;
    class function ComputeECIESPascalCoinEncrypt(const APublicKey: IECPublicKeyParameters; const APayloadToEncrypt: TBytes): TBytes; static; inline;
    class function ComputeECIESPascalCoinDecrypt(const APrivateKey: IECPrivateKeyParameters; const APayloadToDecrypt: TBytes; out ADecryptedPayload: TBytes): boolean; static; inline;
    class function RecreatePublicKeyFromAffineXandAffineYCoord(AKeyType: TKeyType; const AAffineX, AAffineY: TBytes): IECPublicKeyParameters; static;
    class function RecreatePrivateKeyFromByteArray(AKeyType: TKeyType; const APrivateKey: TBytes): IECPrivateKeyParameters; static;
    class function DoEncryptPascalCoinPrivateKey(const APascalCoinPrivateKey, APassword: string): TBytes; static; inline;
    class function DoDecryptPascalCoinPrivateKey(const AEncryptedPascalCoinPrivateKey, APassword: string; out ADecryptedPascalCoinPrivateKey: TBytes): boolean; static;
    class function ExtractPrivateKeyFromDecryptedPascalCoinPrivateKey(const DecryptedPascalCoinPrivateKey: TBytes): TBytes; static; inline;
    class function ExtractAffineXFromPascalCoinPublicKey(const APascalCoinPublicKey: string; out AAffineXBytes: TBytes): boolean; static; inline;
    class function ExtractAffineYFromPascalCoinPublicKey(const APascalCoinPublicKey: string; out AAffineYBytes: TBytes): boolean; static; inline;
    class function GetCurveFromKeyType(AKeyType: TKeyType): IX9ECParameters; static; inline;
    class function EVP_GetSalt(): TBytes; static; inline;
    class function EVP_GetKeyIV(const APasswordBytes, ASaltBytes: TBytes; out AKeyBytes, AIVBytes: TBytes): boolean; static;
    class function ComputeAES256_CBC_PKCS7PADDING_PascalCoinEncrypt(const APlainTextBytes, APasswordBytes: TBytes): TBytes; static;
    class function ComputeAES256_CBC_PKCS7PADDING_PascalCoinDecrypt(const ACipherTextBytes, APasswordBytes: TBytes; out APlainText: TBytes): boolean; static;
    class function GetPascalCoinPublicKeyAsHexString(AKeyType: TKeyType; const AXInput, AYInput: TBytes): string; static; inline;
    class function GetPascalCoinPublicKeyAsBase58(const APascalCoinPublicKey: string): String; static; inline;
    class function GetPascalCoinPrivateKeyAsHexString(AKeyType: TKeyType; const AInput: TBytes): string; static; inline;
    class function GetPascalCoinPrivateKeyEncryptedAsHexString(const APascalCoinPrivateKey, APassword: string): string; static; inline;
    class function GetPrivateKeyPrefix(AKeyType: TKeyType; const AInput: TBytes): TBytes; static; inline;
    class function GetAffineXPrefix(AKeyType: TKeyType; const AInput: TBytes): TBytes; static; inline;
    class function GetAffineYPrefix(const AInput: TBytes): TBytes; static; inline;
    class function UInt32ToLittleEndianByteArrayTwoBytes(AValue: UInt32): TBytes; static; inline;
    class function TwoBytesByteArrayToDec(const AValue: TBytes): Int32; static; inline;
    class function ComputeBase16EncodeUpper(const AInput: TBytes): string; static; inline;
    class function ComputeBase16Decode(const AInput: string): TBytes; static; inline;
    class function ComputeBase58Encode(const AInput: TBytes): string; static; inline;
    class function ComputeBase58Decode(const AInput: string): TBytes; static; inline;
    class function ComputeSHA2_256_ToBytes(const AInput: TBytes): TBytes; static; inline;
    class function GetKeyTypeNumericValue(AKeyType: TKeyType): Int32; static; inline;
    class function IsValidKeyTypeMatch(AValue: Int32; AKeyType: TKeyType): boolean; static; inline;
    class function GenerateECKeyPair(AKeyType: TKeyType): IAsymmetricCipherKeyPair; static;
    class function GetPrivateKey(const AKeyPair: IAsymmetricCipherKeyPair): TBytes; static; inline;
    class function GetPublicKeyAffineX(const AKeyPair: IAsymmetricCipherKeyPair): TBytes; static; inline;
    class function GetPublicKeyAffineY(const AKeyPair: IAsymmetricCipherKeyPair): TBytes; static; inline;
    class constructor PascalCoinKeyTool();
  public

    class procedure GenerateKeyPairAndLog(AKeyType: TKeyType; const APassword: string; var Logger: TStringList); static;
    class procedure EncryptPascalCoinPrivateKey(AKeyType: TKeyType; const APrivateKeyToEncrypt, APassword: string; var Logger: TStringList); static;
    class procedure DecryptPascalCoinPrivateKey(const AEncryptedPascalCoinPrivateKey, APassword: string; var Logger: TStringList); static;
    class procedure EncryptPascalCoinECIESPayload(AKeyType: TKeyType; const APascalCoinBase58PublicKey, APayloadToEncrypt: string; var Logger: TStringList); static;
    class procedure DecryptPascalCoinECIESPayload(AKeyType: TKeyType; const AEncryptedPascalCoinPrivateKey, APrivateKeyPassword, APayloadToDecrypt: string; var Logger: TStringList); static;
    class procedure EncryptPascalCoinAESPayload(const APassword, APayloadToEncrypt: string; var Logger: TStringList); static;
    class procedure DecryptPascalCoinAESPayload(const APassword, APayloadToDecrypt: string; var Logger: TStringList); static;
    class procedure Generate_Recreate_Sign_Verify_ECDSA_Stress_Test(AKeyType: TKeyType; const AMessage: string; AIterationCount: Int32; var Logger: TStringList); static;
  end;

implementation

{ TPascalCoinKeyTool }

class constructor TPascalCoinKeyTool.PascalCoinKeyTool();
begin
  FRandom := TSecureRandom.Create();
end;

class function TPascalCoinKeyTool.ComputeSHA2_256_ToBytes(const AInput: TBytes): TBytes;
begin
  Result := TDigestUtilities.CalculateDigest('SHA-256', AInput);
end;

class function TPascalCoinKeyTool.ComputeBase16EncodeUpper(const AInput: TBytes): string;
begin
  Result := THex.Encode(AInput);
end;

class function TPascalCoinKeyTool.ComputeBase16Decode(const AInput: string): TBytes;
begin
  Result := THex.Decode(AInput);
end;

class function TPascalCoinKeyTool.ComputeBase58Encode(const AInput: TBytes): string;
begin
  Result := TBase58.Encode(AInput);
end;

class function TPascalCoinKeyTool.ComputeBase58Decode(const AInput: string): TBytes;
begin
  Result := TBase58.Decode(AInput);
end;

class function TPascalCoinKeyTool.GetCurveFromKeyType(AKeyType: TKeyType): IX9ECParameters;
var
  CurveName: string;
begin
  CurveName := GetEnumName(TypeInfo(TKeyType), Ord(AKeyType));
  Result := TCustomNamedCurves.GetByName(CurveName);
end;

class function TPascalCoinKeyTool.RetrieveKeyType(AValue: Int32): TKeyType;
begin
  case AValue of
    714: Result := TKeyType.SECP256K1;
    715: Result := TKeyType.SECP384R1;
    716: Result := TKeyType.SECP521R1;
    729: Result := TKeyType.SECT283K1
    else
      raise EArgumentOutOfRangeException.CreateResFmt(@SInvalidKeyType, [AValue]);
  end;
end;

class function TPascalCoinKeyTool.GetKeyTypeNumericValue(AKeyType: TKeyType): Int32;
begin
  case AKeyType of
    TKeyType.SECP256K1: Result := 714;
    TKeyType.SECP384R1: Result := 715;
    TKeyType.SECP521R1: Result := 716;
    TKeyType.SECT283K1: Result := 729
    else
      raise EArgumentOutOfRangeException.CreateResFmt(@SInvalidKeyTypeSelected, [Ord(AKeyType)]);
  end;

end;

class function TPascalCoinKeyTool.IsValidKeyTypeMatch(AValue: Int32; AKeyType: TKeyType): boolean;
var
  LKeyType: TKeyType;
begin
  try
    LKeyType := RetrieveKeyType(AValue);
  except
    on e: Exception do
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := LKeyType = AKeyType;
end;

class function TPascalCoinKeyTool.UInt32ToLittleEndianByteArrayTwoBytes(AValue: UInt32): TBytes;
begin
  Result := System.Copy(TConverters.ReadUInt32AsBytesLE(AValue), 0, 2);
end;

class function TPascalCoinKeyTool.TwoBytesByteArrayToDec(const AValue: TBytes): Int32;
begin
  Result := StrToInt('$' + ComputeBase16EncodeUpper(AValue));
end;

class function TPascalCoinKeyTool.GetAffineXPrefix(AKeyType: TKeyType; const AInput: TBytes): TBytes;
begin
  Result := UInt32ToLittleEndianByteArrayTwoBytes(UInt32(GetKeyTypeNumericValue(AKeyType))) + UInt32ToLittleEndianByteArrayTwoBytes(System.Length(AInput));
end;

class function TPascalCoinKeyTool.GetAffineYPrefix(const AInput: TBytes): TBytes;
begin
  Result := UInt32ToLittleEndianByteArrayTwoBytes(System.Length(AInput));
end;

class function TPascalCoinKeyTool.GetPrivateKeyPrefix(AKeyType: TKeyType; const AInput: TBytes): TBytes;
begin
  Result := UInt32ToLittleEndianByteArrayTwoBytes(UInt32(GetKeyTypeNumericValue(AKeyType))) + UInt32ToLittleEndianByteArrayTwoBytes(System.Length(AInput));
end;

class function TPascalCoinKeyTool.GetSignAsString(ASign: Int32): string;
begin
  case ASign of
   -1: Result := 'Negative';
    0: Result := 'Zero';
    1: Result := 'Positive'
    else
      raise EArgumentOutOfRangeCryptoLibException.CreateResFmt(@SInvalidSign, [ASign]);
  end;
end;

class function TPascalCoinKeyTool.DoECDSASign(const APrivateKey: IECPrivateKeyParameters; const AMessage: TBytes): TCryptoLibGenericArray<TBigInteger>;
var
  Signer: IECDsaSigner;
  Param: IParametersWithRandom;
begin
  Param := TParametersWithRandom.Create(APrivateKey, FRandom);
  Signer := TECDsaSigner.Create();
  Signer.Init(True, Param);
  Result := Signer.GenerateSignature(AMessage);
end;

class function TPascalCoinKeyTool.DoECDSAVerify(const APublicKey: IECPublicKeyParameters; const AMessage: TBytes; const ASig: TCryptoLibGenericArray  <TBigInteger>): boolean;
var
  Signer: IECDsaSigner;
begin
  Signer := TECDsaSigner.Create();
  Signer.Init(False, APublicKey);
  Result := Signer.VerifySignature(AMessage, ASig[0], ASig[1]);
end;

class function TPascalCoinKeyTool.RetrieveKeyTypeInt32FromByteArray(const AInput: TBytes; AOffset: Int32): Int32;
var
  ReversedSlice: TBytes;
begin
  System.SetLength(ReversedSlice, 2);
  TBits.ReverseByteArray(System.Copy(AInput, AOffset, 2), ReversedSlice, Length(ReversedSlice) * System.SizeOf(byte));
  Result := TwoBytesByteArrayToDec(ReversedSlice);
end;

class function TPascalCoinKeyTool.GetPublicKeyType(const APascalCoinBase58PublicKey: string): TKeyType;
var
  LPascalCoinBase58DecodedPublicKey: TBytes;
begin
  LPascalCoinBase58DecodedPublicKey := ComputeBase58Decode(APascalCoinBase58PublicKey);
  Result := RetrieveKeyType(RetrieveKeyTypeInt32FromByteArray(LPascalCoinBase58DecodedPublicKey, 1));
end;

class function TPascalCoinKeyTool.GetPrivateKeyType(const AEncryptedPascalCoinPrivateKey, APassword: string): TKeyType;
var
  LPascalCoinPrivateKey: TBytes;
  DecryptedSuccessfully: boolean;
begin
  Result := Default(TKeyType);
  DecryptedSuccessfully := DoDecryptPascalCoinPrivateKey(AEncryptedPascalCoinPrivateKey, APassword, LPascalCoinPrivateKey);
  if DecryptedSuccessfully then
    Result := RetrieveKeyType(RetrieveKeyTypeInt32FromByteArray(LPascalCoinPrivateKey, 0));
end;

class function TPascalCoinKeyTool.ValidatePascalCoinBase58PublicKeyChecksum(const APascalCoinBase58PublicKey: string): boolean;
var
  Chopped, DecodedPascalCoinBase58Key, OriginalChecksum, CalculatedChecksum: TBytes;
  DecodedPascalCoinBase58KeyLength: Int32;
begin
  DecodedPascalCoinBase58Key := ComputeBase58Decode(APascalCoinBase58PublicKey);
  DecodedPascalCoinBase58KeyLength := System.Length(DecodedPascalCoinBase58Key);
  CalculatedChecksum := System.Copy(DecodedPascalCoinBase58Key, DecodedPascalCoinBase58KeyLength - 4, DecodedPascalCoinBase58KeyLength - 1);
  Chopped := System.Copy(DecodedPascalCoinBase58Key, 1, DecodedPascalCoinBase58KeyLength - 5);
  OriginalChecksum := System.Copy(ComputeSHA2_256_ToBytes(Chopped), 0, 4);
  Result := TArrayUtils.AreEqual(OriginalChecksum, CalculatedChecksum);
end;

class function TPascalCoinKeyTool.ValidatePublicKeyHeader(AKeyType: TKeyType; const AInput: TBytes; out AErrorMessage: string): boolean;
var
  ExtractedValue: Int32;
begin
  Result := False;
  ExtractedValue := RetrieveKeyTypeInt32FromByteArray(AInput, 1);

  case ExtractedValue of
    714, 715, 716, 729:
      if IsValidKeyTypeMatch(ExtractedValue, AKeyType) then
      begin
        Result := True;
        Exit;
      end
      else
      begin
        AErrorMessage := 'PascalCoin Public Key Header Does Not Match Selected Key Type.';
        Exit;
      end
    else
    begin
      AErrorMessage := 'Invalid or Corrupted PascalCoin Public Key.';
      Exit;
    end;

  end;

end;

class function TPascalCoinKeyTool.ValidatePrivateKeyHeader(AKeyType: TKeyType; const AInput: TBytes; out AErrorMessage: string): boolean;
var
  ExtractedValue: Int32;
begin
  Result := False;
  ExtractedValue := RetrieveKeyTypeInt32FromByteArray(AInput, 0);

  case ExtractedValue of
    714, 715, 716, 729:
      if IsValidKeyTypeMatch(ExtractedValue, AKeyType) then
      begin
        Result := True;
        Exit;
      end
      else
      begin
        AErrorMessage := 'PascalCoin Private Key Header Does Not Match Selected Key Type.';
        Exit;
      end
    else
    begin
      AErrorMessage := 'Invalid or Corrupted PascalCoin Private Key.';
      Exit;
    end;

  end;

end;

class function TPascalCoinKeyTool.IsValidHexString(const AInput: string): boolean;
var
  c: char;
begin
  Result := True;
  if ((System.Length(AInput) and 1) <> 0) then
  begin
    Result := False;
    Exit;
  end;
  for c in AInput do
    if (not (((c >= '0') and (c <= '9')) or ((c >= 'A') and (c <= 'F')) or
      ((c >= 'a') and (c <= 'f')))) then
    begin
      Result := False;
      Exit;
    end;
end;

class function TPascalCoinKeyTool.GetIESCipherParameters: IIESWithCipherParameters;
var
  Derivation, Encoding, IVBytes: TBytes;
  MacKeySizeInBits, CipherKeySizeInBits: Int32;
  UsePointCompression: boolean;
begin
  // Set up IES Cipher Parameters For Compatibility With PascalCoin Current Implementation

  // The derivation and encoding vectors are used when initialising the KDF and MAC.
  // They're optional but if used then they need to be known by the other user so that
  // they can decrypt the ciphertext and verify the MAC correctly. The security is based
  // on the shared secret coming from the (static-ephemeral) ECDH key agreement.
  Derivation := nil;

  Encoding := nil;

  System.SetLength(IVBytes, 16); // using Zero Initialized IV for compatibility

  MacKeySizeInBits := 32 * 8;

  // Since we are using AES256_CBC for compatibility
  CipherKeySizeInBits := 32 * 8;

  // whether to use point compression when deriving the octets string
  // from a point or not in the EphemeralKeyPairGenerator
  UsePointCompression := True; // for compatibility

  Result := TIESWithCipherParameters.Create(Derivation, Encoding,
    MacKeySizeInBits, CipherKeySizeInBits, IVBytes, UsePointCompression);
end;

class function TPascalCoinKeyTool.GetECIESPascalCoinCompatibilityEngine(): IPascalCoinIESEngine;
var
  cipher: IBufferedBlockCipher;
  AesEngine: IAesEngine;
  blockCipher: ICbcBlockCipher;
  ECDHBasicAgreementInstance: IECDHBasicAgreement;
  KDFInstance: IPascalCoinECIESKdfBytesGenerator;
  DigestMACInstance: IMac;

begin
  // Set up IES Cipher Engine For Compatibility With PascalCoin

  ECDHBasicAgreementInstance := TECDHBasicAgreement.Create();

  KDFInstance := TPascalCoinECIESKdfBytesGenerator.Create
    (TDigestUtilities.GetDigest('SHA-512'));

  DigestMACInstance := TMacUtilities.GetMac('HMAC-MD5');

  // Set Up Block Cipher
  AesEngine := TAesEngine.Create(); // AES Engine

  blockCipher := TCbcBlockCipher.Create(AesEngine); // CBC

  cipher := TPaddedBufferedBlockCipher.Create(blockCipher,
    TZeroBytePadding.Create() as IZeroBytePadding); // ZeroBytePadding

  Result := TPascalCoinIESEngine.Create(ECDHBasicAgreementInstance, KDFInstance,
    DigestMACInstance, cipher);
end;

class function TPascalCoinKeyTool.ComputeECIESPascalCoinEncrypt(const APublicKey: IECPublicKeyParameters; const APayloadToEncrypt: TBytes): TBytes;
var
  CipherEncrypt: IIESCipher;
begin
  // Encryption
  CipherEncrypt := TIESCipher.Create(GetECIESPascalCoinCompatibilityEngine());
  CipherEncrypt.Init(True, APublicKey, GetIESCipherParameters(), FRandom);
  Result := CipherEncrypt.DoFinal(APayloadToEncrypt);
end;

class function TPascalCoinKeyTool.ComputeECIESPascalCoinDecrypt(const APrivateKey: IECPrivateKeyParameters; const APayloadToDecrypt: TBytes; out ADecryptedPayload: TBytes): boolean;
var
  CipherDecrypt: IIESCipher;
begin
  try
    // Decryption
    CipherDecrypt := TIESCipher.Create(GetECIESPascalCoinCompatibilityEngine());
    CipherDecrypt.Init(False, APrivateKey, GetIESCipherParameters(), FRandom);
    ADecryptedPayload := System.Copy(CipherDecrypt.DoFinal(APayloadToDecrypt));
    Result := True;
  except
    Result := False;
  end;
end;

class function TPascalCoinKeyTool.RecreatePublicKeyFromAffineXandAffineYCoord(AKeyType: TKeyType; const AAffineX, AAffineY: TBytes): IECPublicKeyParameters;
var
  domain: IECDomainParameters;
  LCurve: IX9ECParameters;
  point: IECPoint;
  BigXCoord, BigYCoord: TBigInteger;
begin
  LCurve := GetCurveFromKeyType(AKeyType);
  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);

  BigXCoord := TBigInteger.Create(1, AAffineX);
  BigYCoord := TBigInteger.Create(1, AAffineY);

  point := LCurve.Curve.CreatePoint(BigXCoord, BigYCoord);

  Result := TECPublicKeyParameters.Create('ECDSA', point, domain);
end;

class function TPascalCoinKeyTool.RecreatePrivateKeyFromByteArray(AKeyType: TKeyType; const APrivateKey: TBytes): IECPrivateKeyParameters;
var
  domain: IECDomainParameters;
  LCurve: IX9ECParameters;
  PrivD: TBigInteger;
begin
  LCurve := GetCurveFromKeyType(AKeyType);
  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);

  PrivD := TBigInteger.Create(1, APrivateKey);

  Result := TECPrivateKeyParameters.Create('ECDSA',
    PrivD, domain);
end;

class function TPascalCoinKeyTool.DoEncryptPascalCoinPrivateKey(const APascalCoinPrivateKey, APassword: string): TBytes;
var
  PlainTextBytes, PasswordBytes: TBytes;
begin
  PlainTextBytes := ComputeBase16Decode(APascalCoinPrivateKey);
  PasswordBytes := TConverters.ConvertStringToBytes(APassword, TEncoding.UTF8);
  Result := ComputeAES256_CBC_PKCS7PADDING_PascalCoinEncrypt(PlainTextBytes,
    PasswordBytes);
end;

class function TPascalCoinKeyTool.DoDecryptPascalCoinPrivateKey(const AEncryptedPascalCoinPrivateKey, APassword: string; out ADecryptedPascalCoinPrivateKey: TBytes): boolean;
var
  CipherTextBytes, PasswordBytes: TBytes;
begin
  CipherTextBytes := ComputeBase16Decode(AEncryptedPascalCoinPrivateKey);
  PasswordBytes := TConverters.ConvertStringToBytes(APassword, TEncoding.UTF8);
  Result := ComputeAES256_CBC_PKCS7PADDING_PascalCoinDecrypt(CipherTextBytes,
    PasswordBytes, ADecryptedPascalCoinPrivateKey);
end;

class function TPascalCoinKeyTool.ExtractPrivateKeyFromDecryptedPascalCoinPrivateKey
  (const DecryptedPascalCoinPrivateKey: TBytes): TBytes;
begin
  Result := System.Copy(DecryptedPascalCoinPrivateKey, 4, System.Length(DecryptedPascalCoinPrivateKey) - 4);
end;

class function TPascalCoinKeyTool.ExtractAffineXFromPascalCoinPublicKey(const APascalCoinPublicKey: string; out AAffineXBytes: TBytes): boolean;
var
  AffineXLength: Int32;
  LPascalCoinPublicKeyBytes: TBytes;
begin
  LPascalCoinPublicKeyBytes := ComputeBase16Decode(APascalCoinPublicKey);
  AffineXLength := Int32(System.Copy(LPascalCoinPublicKeyBytes, 3, 1)[0]);
  AAffineXBytes := System.Copy(LPascalCoinPublicKeyBytes, 5, AffineXLength);
  Result := System.Length(AAffineXBytes) = AffineXLength;
end;

class function TPascalCoinKeyTool.ExtractAffineYFromPascalCoinPublicKey(const APascalCoinPublicKey: string; out AAffineYBytes: TBytes): boolean;
var
  AffineXLength, AffineYLength, Offset: Int32;
  LPascalCoinPublicKeyBytes: TBytes;
begin
  LPascalCoinPublicKeyBytes := ComputeBase16Decode(APascalCoinPublicKey);
  AffineXLength := Int32(System.Copy(LPascalCoinPublicKeyBytes, 3, 1)[0]);
  Offset := 5 + AffineXLength;
  AffineYLength := Int32(System.Copy(LPascalCoinPublicKeyBytes, Offset, 1)[0]);
  AAffineYBytes := System.Copy(LPascalCoinPublicKeyBytes, Offset + 2, AffineYLength);
  Result := System.Length(AAffineYBytes) = AffineYLength;
end;

class function TPascalCoinKeyTool.EVP_GetSalt(): TBytes;
begin
  System.SetLength(Result, PKCS5_SALT_LEN);
  FRandom.NextBytes(Result);
end;

class function TPascalCoinKeyTool.EVP_GetKeyIV(const APasswordBytes, ASaltBytes: TBytes; out AKeyBytes, AIVBytes: TBytes): boolean;
var
  LKey, LIV: Int32;
  LDigest: IDigest;
begin
  LKey := 32; // AES256 CBC Key Length
  LIV := 16; // AES256 CBC IV Length
  System.SetLength(AKeyBytes, LKey);
  System.SetLength(AIVBytes, LKey);
  // Max size to start then reduce it at the end
  LDigest := TDigestUtilities.GetDigest('SHA-256'); // SHA2_256
  System.Assert(LDigest.GetDigestSize >= LKey);
  System.Assert(LDigest.GetDigestSize >= LIV);
  // Derive Key First
  LDigest.BlockUpdate(APasswordBytes, 0, System.Length(APasswordBytes));
  if ASaltBytes <> Nil then
  begin
    LDigest.BlockUpdate(ASaltBytes, 0, System.Length(ASaltBytes));
  end;
  LDigest.DoFinal(AKeyBytes, 0);
  // Derive IV Next
  LDigest.Reset();
  LDigest.BlockUpdate(AKeyBytes, 0, System.Length(AKeyBytes));
  LDigest.BlockUpdate(APasswordBytes, 0, System.Length(APasswordBytes));
  if ASaltBytes <> Nil then
  begin
    LDigest.BlockUpdate(ASaltBytes, 0, System.Length(ASaltBytes));
  end;
  LDigest.DoFinal(AIVBytes, 0);

  System.SetLength(AIVBytes, LIV);
  Result := True;
end;

class function TPascalCoinKeyTool.ComputeAES256_CBC_PKCS7PADDING_PascalCoinEncrypt
  (const APlainTextBytes, APasswordBytes: TBytes): TBytes;
var
  SaltBytes, KeyBytes, IVBytes, Buf: TBytes;
  KeyParametersWithIV: IParametersWithIV;
  cipher: IBufferedCipher;
  LBlockSize, LBufStart, Count: Int32;
begin
  SaltBytes := EVP_GetSalt();
  EVP_GetKeyIV(APasswordBytes, SaltBytes, KeyBytes, IVBytes);
  cipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
  KeyParametersWithIV := TParametersWithIV.Create
    (TParameterUtilities.CreateKeyParameter('AES', KeyBytes), IVBytes);

  cipher.Init(True, KeyParametersWithIV); // init encryption cipher
  LBlockSize := cipher.GetBlockSize;

  System.SetLength(Buf, System.Length(APlainTextBytes) + LBlockSize + SALT_MAGIC_LEN +
    PKCS5_SALT_LEN);

  LBufStart := 0;

  System.Move(TConverters.ConvertStringToBytes(SALT_MAGIC, TEncoding.UTF8)[0], Buf[LBufStart],
    SALT_MAGIC_LEN * System.SizeOf(byte));
  System.Inc(LBufStart, SALT_MAGIC_LEN);
  System.Move(SaltBytes[0], Buf[LBufStart],
    PKCS5_SALT_LEN * System.SizeOf(byte));
  System.Inc(LBufStart, PKCS5_SALT_LEN);

  Count := cipher.ProcessBytes(APlainTextBytes, 0, System.Length(APlainTextBytes), Buf,
    LBufStart);
  System.Inc(LBufStart, Count);
  Count := cipher.DoFinal(Buf, LBufStart);
  System.Inc(LBufStart, Count);

  System.SetLength(Buf, LBufStart);
  Result := Buf;
end;

class function TPascalCoinKeyTool.ComputeAES256_CBC_PKCS7PADDING_PascalCoinDecrypt
  (const ACipherTextBytes, APasswordBytes: TBytes; out APlainText: TBytes): boolean;
var
  SaltBytes, KeyBytes, IVBytes, Buf, Chopped: TBytes;
  KeyParametersWithIV: IParametersWithIV;
  cipher: IBufferedCipher;
  LBufStart, LSrcStart, Count: Int32;
begin
  try
    System.SetLength(SaltBytes, SALT_SIZE);
    // First read the magic text and the salt - if any
    Chopped := System.Copy(ACipherTextBytes, 0, SALT_MAGIC_LEN);
    if (System.Length(ACipherTextBytes) >= SALT_MAGIC_LEN) and
      (TArrayUtils.AreEqual(Chopped, TConverters.ConvertStringToBytes(SALT_MAGIC, TEncoding.UTF8))) then
    begin
      System.Move(ACipherTextBytes[SALT_MAGIC_LEN], SaltBytes[0], SALT_SIZE);
      if not EVP_GetKeyIV(APasswordBytes, SaltBytes, KeyBytes, IVBytes) then
      begin
        Result := False;
        Exit;
      end;
      LSrcStart := SALT_MAGIC_LEN + SALT_SIZE;
    end
    else
    begin
      if not EVP_GetKeyIV(APasswordBytes, nil, KeyBytes, IVBytes) then
      begin
        Result := False;
        Exit;
      end;
      LSrcStart := 0;
    end;

    cipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
    KeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', KeyBytes), IVBytes);

    cipher.Init(False, KeyParametersWithIV); // init decryption cipher

    System.SetLength(Buf, System.Length(ACipherTextBytes));

    LBufStart := 0;

    Count := cipher.ProcessBytes(ACipherTextBytes, LSrcStart, System.Length(ACipherTextBytes) - LSrcStart, Buf, LBufStart);
    System.Inc(LBufStart, Count);
    Count := cipher.DoFinal(Buf, LBufStart);
    System.Inc(LBufStart, Count);

    System.SetLength(Buf, LBufStart);

    APlainText := System.Copy(Buf);

    Result := True;
  except
    Result := False;
  end;
end;

class function TPascalCoinKeyTool.GetPascalCoinPublicKeyAsHexString(AKeyType: TKeyType; const AXInput, AYInput: TBytes): string;
var
  PartX, PartY, TotalPart: TBytes;
begin
  PartX := TArrayUtils.AddByteArray(GetAffineXPrefix(AKeyType, AXInput), AXInput);
  PartY := TArrayUtils.AddByteArray(GetAffineYPrefix(AYInput), AYInput);
  TotalPart := TArrayUtils.AddByteArray(PartX, PartY);
  Result := ComputeBase16EncodeUpper(TotalPart);
end;

class function TPascalCoinKeyTool.GetPascalCoinPublicKeyAsBase58(const APascalCoinPublicKey: string): String;
const
  B58_PUBKEY_PREFIX: string = '01';
var
  PreBase58PublicKeyBytes, PascalCoinPublicKeyBytes, Base58PublicKeyBytes: TBytes;
begin
  PascalCoinPublicKeyBytes := ComputeBase16Decode(APascalCoinPublicKey);
  Base58PublicKeyBytes := ComputeBase16Decode(B58_PUBKEY_PREFIX);
  PreBase58PublicKeyBytes := TArrayUtils.AddByteArray(TArrayUtils.AddByteArray(Base58PublicKeyBytes, PascalCoinPublicKeyBytes), System.Copy(ComputeSHA2_256_ToBytes(PascalCoinPublicKeyBytes), 0, 4));
  Result := ComputeBase58Encode(PreBase58PublicKeyBytes);
end;

class function TPascalCoinKeyTool.GetPascalCoinPrivateKeyAsHexString(AKeyType: TKeyType; const AInput: TBytes): string;
begin
  Result := ComputeBase16EncodeUpper(TArrayUtils.AddByteArray(GetPrivateKeyPrefix(AKeyType, AInput), AInput));
end;

class function TPascalCoinKeyTool.GetPascalCoinPrivateKeyEncryptedAsHexString(const APascalCoinPrivateKey, APassword: string): string;
var
  PascalCoinPrivateKeyBytes, PasswordBytes: TBytes;
begin
  PascalCoinPrivateKeyBytes := ComputeBase16Decode(APascalCoinPrivateKey);
  PasswordBytes := TConverters.ConvertStringToBytes(APassword, TEncoding.UTF8);
  Result := ComputeBase16EncodeUpper(ComputeAES256_CBC_PKCS7PADDING_PascalCoinEncrypt(PascalCoinPrivateKeyBytes,
    PasswordBytes));
end;

class function TPascalCoinKeyTool.GenerateECKeyPair(AKeyType: TKeyType): IAsymmetricCipherKeyPair;
var
  LCurve: IX9ECParameters;
  Domain: IECDomainParameters;
  KeyPairGeneratorInstance: IAsymmetricCipherKeyPairGenerator;
begin
  LCurve := GetCurveFromKeyType(AKeyType);
  KeyPairGeneratorInstance := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  Domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);
  KeyPairGeneratorInstance.Init(TECKeyGenerationParameters.Create(Domain,
    FRandom) as IECKeyGenerationParameters);
  Result := KeyPairGeneratorInstance.GenerateKeyPair();
end;

class function TPascalCoinKeyTool.GetPrivateKey(const AKeyPair: IAsymmetricCipherKeyPair): TBytes;
var
  LPrivateKey: IECPrivateKeyParameters;
begin
  LPrivateKey := AKeyPair.&Private as IECPrivateKeyParameters;
  Result := LPrivateKey.D.ToByteArray();
end;

class function TPascalCoinKeyTool.GetPublicKeyAffineX(const AKeyPair: IAsymmetricCipherKeyPair): TBytes;
var
  LPublicKey: IECPublicKeyParameters;
begin
  LPublicKey := AKeyPair.&Public as IECPublicKeyParameters;
  Result := LPublicKey.Q.AffineXCoord.ToBigInteger().ToByteArray();
end;

class function TPascalCoinKeyTool.GetPublicKeyAffineY(const AKeyPair: IAsymmetricCipherKeyPair): TBytes;
var
  LPublicKey: IECPublicKeyParameters;
begin
  LPublicKey := AKeyPair.&Public as IECPublicKeyParameters;
  Result := LPublicKey.Q.AffineYCoord.ToBigInteger().ToByteArray();
end;

class procedure TPascalCoinKeyTool.GenerateKeyPairAndLog(AKeyType: TKeyType; const APassword: string; var Logger: TStringList);
var
  LKeyPair: IAsymmetricCipherKeyPair;
  LPrivateKey, LPublicKeyXCoord, LPublicKeyYCoord: TBytes;
  LPascalCoinPrivateKey, LPascalCoinPrivateKeyEncrypted, LPascalCoinPublicKey, LPascalCoinPublicKeyBase58: string;
begin
  if not Assigned(Logger) then
    Logger := TStringList.Create();

  Logger.Clear;
  Logger.Append('================================================= START ==================================================');

  Logger.Append(Format('Selected Key Type is %s', [GetEnumName(TypeInfo(TKeyType), Ord(AKeyType))]));
  LKeyPair := GenerateECKeyPair(AKeyType);
  Logger.Append(Format('%s ECKeyPair Generated Successfully.', [GetEnumName(TypeInfo(TKeyType), Ord(AKeyType))]));

  LPrivateKey := GetPrivateKey(LKeyPair);
  Logger.Append(Format('Private Key is %s', [ComputeBase16EncodeUpper(LPrivateKey)]));
  LPublicKeyXCoord := GetPublicKeyAffineX(LKeyPair);
  Logger.Append(Format('Public Key XCoord is %s', [ComputeBase16EncodeUpper(LPublicKeyXCoord)]));
  LPublicKeyYCoord := GetPublicKeyAffineY(LKeyPair);
  Logger.Append(Format('Public Key YCoord is %s', [ComputeBase16EncodeUpper(LPublicKeyYCoord)]));

  LPascalCoinPrivateKey := GetPascalCoinPrivateKeyAsHexString(AKeyType, LPrivateKey);
  Logger.Append(Format('PascalCoin Private Key is %s', [LPascalCoinPrivateKey]));

  Logger.Append(Format('PascalCoin Private Key Encryption Password is %s', [APassword]));
  LPascalCoinPrivateKeyEncrypted := GetPascalCoinPrivateKeyEncryptedAsHexString(LPascalCoinPrivateKey, APassword);
  Logger.Append('PascalCoin Private Key Encrypted Successfully.');
  Logger.Append(Format('PascalCoin Encrypted Private Key In Hex is %s', [LPascalCoinPrivateKeyEncrypted]));

  LPascalCoinPublicKey := GetPascalCoinPublicKeyAsHexString(AKeyType, LPublicKeyXCoord, LPublicKeyYCoord);
  Logger.Append(Format('PascalCoin Public Key is %s', [LPascalCoinPublicKey]));

  LPascalCoinPublicKeyBase58 := GetPascalCoinPublicKeyAsBase58(LPascalCoinPublicKey);
  Logger.Append(Format('PascalCoin Public Key in Base58 is %s', [LPascalCoinPublicKeyBase58]));

  Logger.Append('================================================== END ===================================================');

end;

class procedure TPascalCoinKeyTool.EncryptPascalCoinPrivateKey(AKeyType: TKeyType; const APrivateKeyToEncrypt, APassword: string; var Logger: TStringList);
var
  EncryptedCipherText: TBytes;
  LPascalCoinPrivateKey, LPascalCoinPrivateKeyEncrypted: string;
begin
  if not Assigned(Logger) then
    Logger := TStringList.Create();

  Logger.Clear;
  Logger.Append('================================================= START ==================================================');

  Logger.Append(Format('Selected Key Type is %s', [GetEnumName(TypeInfo(TKeyType), Ord(AKeyType))]));

  Logger.Append(Format('Private Key is %s', [APrivateKeyToEncrypt]));

  if (not (IsValidHexString(APrivateKeyToEncrypt))) then
  begin
    Logger.Append(Format('"%s" is an Invalid HexString', [APrivateKeyToEncrypt]));
    Logger.Append('================================================== END ===================================================');
    Exit;
  end;

  LPascalCoinPrivateKey := ComputeBase16EncodeUpper(TArrayUtils.AddByteArray(GetPrivateKeyPrefix(AKeyType, ComputeBase16Decode(APrivateKeyToEncrypt)), ComputeBase16Decode(APrivateKeyToEncrypt)));
  Logger.Append(Format('PascalCoin Private Key is %s', [LPascalCoinPrivateKey]));
  Logger.Append(Format('Password To Use For Encryption is %s', [APassword]));

  EncryptedCipherText := DoEncryptPascalCoinPrivateKey(LPascalCoinPrivateKey, APassword);

  LPascalCoinPrivateKeyEncrypted := ComputeBase16EncodeUpper(EncryptedCipherText);
  Logger.Append('PascalCoin Private Key Encrypted Successfully.');
  Logger.Append(Format('Encrypted PascalCoin Private Key is %s', [LPascalCoinPrivateKeyEncrypted]));

  Logger.Append('================================================== END ===================================================');
end;

class procedure TPascalCoinKeyTool.DecryptPascalCoinPrivateKey(const AEncryptedPascalCoinPrivateKey, APassword: string; var Logger: TStringList);
var
  DecryptedCipherText: TBytes;
  DecryptedSuccessfully: boolean;
  LPascalCoinPrivateKey, LPrivateKey: string;
begin
  if not Assigned(Logger) then
    Logger := TStringList.Create();

  Logger.Clear;
  Logger.Append('================================================= START ==================================================');

  Logger.Append(Format('PascalCoin Encrypted Private Key is %s', [AEncryptedPascalCoinPrivateKey]));
  Logger.Append(Format('Password To Use For Decryption is %s', [APassword]));

  if (not (IsValidHexString(AEncryptedPascalCoinPrivateKey))) then
  begin
    Logger.Append(Format('"%s" is an Invalid HexString', [AEncryptedPascalCoinPrivateKey]));
    Logger.Append('================================================== END ===================================================');
    Exit;
  end;

  DecryptedSuccessfully := DoDecryptPascalCoinPrivateKey(AEncryptedPascalCoinPrivateKey,
    APassword, DecryptedCipherText);
  if DecryptedSuccessfully then
  begin
    LPascalCoinPrivateKey := ComputeBase16EncodeUpper(DecryptedCipherText);
    Logger.Append('PascalCoin Private Key Decrypted Successfully.');
    Logger.Append(Format('PascalCoin Private Key is %s', [LPascalCoinPrivateKey]));

    LPrivateKey := ComputeBase16EncodeUpper(ExtractPrivateKeyFromDecryptedPascalCoinPrivateKey(DecryptedCipherText));
    Logger.Append(Format('Private Key is %s', [LPrivateKey]));
  end
  else
    Logger.Append('An Error Occurred While Decrypting PascalCoin Private Key.');

  Logger.Append('================================================== END ===================================================');
end;

class procedure TPascalCoinKeyTool.EncryptPascalCoinECIESPayload(AKeyType: TKeyType; const APascalCoinBase58PublicKey, APayloadToEncrypt: string; var Logger: TStringList);
var
  LPascalCoinPublicKey, ErrorMessage: string;
  AffineXCoord, AffineYCoord, PayloadToEncrypt, EncryptedPayload: TBytes;
  RecreatedPublicKey: IECPublicKeyParameters;
begin
  if not Assigned(Logger) then
    Logger := TStringList.Create();

  Logger.Clear;
  Logger.Append('================================================= START ==================================================');

  Logger.Append(Format('Selected Key Type is %s', [GetEnumName(TypeInfo(TKeyType), Ord(AKeyType))]));

  Logger.Append(Format('PascalCoin Base58 Public Key is %s', [APascalCoinBase58PublicKey]));

  if (not ValidatePascalCoinBase58PublicKeyChecksum(APascalCoinBase58PublicKey)) then
  begin
    Logger.Append('PascalCoinBase58 Public Key Checksum is Invalid');
    Logger.Append('================================================== END ===================================================');
    Exit;
  end;

  LPascalCoinPublicKey := ComputeBase16EncodeUpper(ComputeBase58Decode(APascalCoinBase58PublicKey));

  Logger.Append(Format('PascalCoin Public Key is %s', [LPascalCoinPublicKey]));

  if (not ValidatePublicKeyHeader(AKeyType, ComputeBase16Decode(LPascalCoinPublicKey), ErrorMessage)) then
  begin
    Logger.Append(Format('Error Occured While Encrypting Payload. [%s]', [ErrorMessage]));
    Logger.Append('================================================== END ===================================================');
    Exit;
  end;

  Logger.Append(Format('Payload To Encrypt is "%s"', [APayloadToEncrypt]));

  PayloadToEncrypt := TConverters.ConvertStringToBytes(APayloadToEncrypt, TEncoding.UTF8);

  if not ExtractAffineXFromPascalCoinPublicKey(LPascalCoinPublicKey, AffineXCoord) then
  begin
    Logger.Append('Error Extracting AffineX Coord From PascalCoin Public Key.');
    Logger.Append('================================================== END ===================================================');
    Exit;
  end;
  Logger.Append(Format('PascalCoin Public Key AffineX Coord is %s', [ComputeBase16EncodeUpper(AffineXCoord)]));

  if not ExtractAffineYFromPascalCoinPublicKey(LPascalCoinPublicKey, AffineYCoord) then
  begin
    Logger.Append('Error Extracting AffineY Coord From PascalCoin Public Key.');
    Logger.Append('================================================== END ===================================================');
    Exit;
  end;
  Logger.Append(Format('PascalCoin Public Key AffineY Coord is %s', [ComputeBase16EncodeUpper(AffineYCoord)]));

  RecreatedPublicKey := RecreatePublicKeyFromAffineXandAffineYCoord(AKeyType, AffineXCoord, AffineYCoord);

  Logger.Append('Public Key Recreated From PascalCoin Public Key AffineX and AffineY Coords.');

  EncryptedPayload := ComputeECIESPascalCoinEncrypt(RecreatedPublicKey, PayloadToEncrypt);

  Logger.Append('Payload Encrypted Successfully.');
  Logger.Append(Format('Encrypted Payload is %s', [ComputeBase16EncodeUpper(EncryptedPayload)]));

  Logger.Append('================================================== END ===================================================');
end;

class procedure TPascalCoinKeyTool.DecryptPascalCoinECIESPayload(AKeyType: TKeyType; const AEncryptedPascalCoinPrivateKey, APrivateKeyPassword, APayloadToDecrypt: string; var Logger: TStringList);
var
  PascalCoinPrivateKey, DecryptedPayload, PayloadToDecrypt: TBytes;
  DecryptedSuccessfully: boolean;
  RecreatedPrivateKey: IECPrivateKeyParameters;
  ErrorMessage: string;

begin
  if not Assigned(Logger) then
    Logger := TStringList.Create();

  Logger.Clear;
  Logger.Append('================================================= START ==================================================');

  Logger.Append(Format('Selected Key Type is %s', [GetEnumName(TypeInfo(TKeyType), Ord(AKeyType))]));

  Logger.Append(Format('Encrypted PascalCoin Private Key is %s', [AEncryptedPascalCoinPrivateKey]));

  if (not (IsValidHexString(AEncryptedPascalCoinPrivateKey))) then
  begin
    Logger.Append(Format('"%s" is an Invalid HexString', [AEncryptedPascalCoinPrivateKey]));
    Logger.Append('================================================== END ===================================================');
    Exit;
  end;

  DecryptedSuccessfully := DoDecryptPascalCoinPrivateKey(AEncryptedPascalCoinPrivateKey, APrivateKeyPassword, PascalCoinPrivateKey);

  if DecryptedSuccessfully then
  begin
    Logger.Append('PascalCoin Private Key Decrypted Successfully.');
    Logger.Append(Format('PascalCoin Private Key is "%s"', [ComputeBase16EncodeUpper(PascalCoinPrivateKey)]));
  end
  else
  begin
    Logger.Append('An Error Occurred While Decrypting PascalCoin Private Key.');
    Logger.Append('================================================== END ===================================================');
    Exit;
  end;

  if (not ValidatePrivateKeyHeader(AKeyType, PascalCoinPrivateKey, ErrorMessage)) then
  begin
    Logger.Append(Format('Error Occured While Decrypting Payload. [%s]', [ErrorMessage]));
    Logger.Append('================================================== END ===================================================');
    Exit;
  end;

  RecreatedPrivateKey := RecreatePrivateKeyFromByteArray(AKeyType, ExtractPrivateKeyFromDecryptedPascalCoinPrivateKey(PascalCoinPrivateKey));

  Logger.Append('Private Key Recreated');

  if (not (IsValidHexString(APayloadToDecrypt))) then
  begin
    Logger.Append(Format('"%s" is an Invalid HexString', [APayloadToDecrypt]));
    Logger.Append('================================================== END ===================================================');
    Exit;
  end;

  PayloadToDecrypt := ComputeBase16Decode(APayloadToDecrypt);

  if ComputeECIESPascalCoinDecrypt(RecreatedPrivateKey, PayloadToDecrypt, DecryptedPayload) then
  begin
    Logger.Append('Payload Decrypted Successfully.');
    Logger.Append(Format('Decrypted Payload is "%s"', [TConverters.ConvertBytesToString(DecryptedPayload, TEncoding.UTF8)]));
  end
  else
    Logger.Append('An Error Occured While Decrypting Payload.');

  Logger.Append('================================================== END ===================================================');
end;

class procedure TPascalCoinKeyTool.EncryptPascalCoinAESPayload(const APassword, APayloadToEncrypt: string; var Logger: TStringList);
var
  PasswordBytes, PayloadToEncryptBytes, EncryptedPayloadBytes: TBytes;
begin
  if not Assigned(Logger) then
    Logger := TStringList.Create();

  Logger.Clear;
  Logger.Append('================================================= START ==================================================');

  Logger.Append(Format('Encryption Password is %s', [APassword]));

  PasswordBytes := TConverters.ConvertStringToBytes(APassword, TEncoding.UTF8);

  Logger.Append(Format('Payload to Encrypt is "%s"', [APayloadToEncrypt]));

  PayloadToEncryptBytes := TConverters.ConvertStringToBytes(APayloadToEncrypt, TEncoding.UTF8);

  EncryptedPayloadBytes := ComputeAES256_CBC_PKCS7PADDING_PascalCoinEncrypt(PayloadToEncryptBytes, PasswordBytes);

  Logger.Append('Payload Encrypted Successfully.');

  Logger.Append(Format('Encrypted Payload is %s', [ComputeBase16EncodeUpper(EncryptedPayloadBytes)]));

  Logger.Append('================================================== END ===================================================');
end;

class procedure TPascalCoinKeyTool.DecryptPascalCoinAESPayload(const APassword, APayloadToDecrypt: string; var Logger: TStringList);
var
  PasswordBytes, PayloadToDecryptBytes, DecryptedPayloadBytes: TBytes;
  DecryptedSuccessfully: boolean;
begin
  if not Assigned(Logger) then
    Logger := TStringList.Create();

  Logger.Clear;
  Logger.Append('================================================= START ==================================================');

  Logger.Append(Format('Decryption Password is %s', [APassword]));

  PasswordBytes := TConverters.ConvertStringToBytes(APassword, TEncoding.UTF8);

  Logger.Append(Format('Payload to Decrypt is "%s"', [APayloadToDecrypt]));

  if (not (IsValidHexString(APayloadToDecrypt))) then
  begin
    Logger.Append(Format('"%s" is an Invalid HexString', [APayloadToDecrypt]));
    Logger.Append('================================================== END ===================================================');
    Exit;
  end;

  PayloadToDecryptBytes := ComputeBase16Decode(APayloadToDecrypt);

  DecryptedSuccessfully := ComputeAES256_CBC_PKCS7PADDING_PascalCoinDecrypt(PayloadToDecryptBytes, PasswordBytes, DecryptedPayloadBytes);

  if DecryptedSuccessfully then
  begin
    Logger.Append('Payload Decrypted Successfully.');
    Logger.Append(Format('Decrypted Payload is "%s"', [TConverters.ConvertBytesToString(DecryptedPayloadBytes, TEncoding.UTF8)]));
  end
  else
    Logger.Append('An Error Occurred While Decrypting Payload.');

  Logger.Append('================================================== END ===================================================');
end;

class procedure TPascalCoinKeyTool.Generate_Recreate_Sign_Verify_ECDSA_Stress_Test(AKeyType: TKeyType; const AMessage: string; AIterationCount: Int32; var Logger: TStringList);
var
  LKeyPair: IAsymmetricCipherKeyPair;
  LPrivateKey, LPublicKeyXCoord, LPublicKeyYCoord, LMessage: TBytes;
  LPrivateKeyBigInteger, LPublicKeyXCoordBigInteger, LPublicKeyYCoordBigInteger: TBigInteger;
  LSig: TCryptoLibGenericArray<TBigInteger>;
  PrivateKeyRecreated: IECPrivateKeyParameters;
  PublicKeyRecreated: IECPublicKeyParameters;
  PassVerify: boolean;
  Idx, PassedCount: Int32;
begin
  if not Assigned(Logger) then
    Logger := TStringList.Create();

  Logger.Clear;
  Logger.Append('================================================= START ==================================================');

  Logger.Append('Please Be Patient. This Operation May Take a While For Large Iteration Count.');

  Logger.Append(Format('Selected Key Type is %s', [GetEnumName(TypeInfo(TKeyType), Ord(AKeyType))]));

  Logger.Append(Format('Message To Sign is "%s"', [AMessage]));

  Logger.Append(Format('Iteration Count is %d', [AIterationCount]));

  LMessage := TConverters.ConvertStringToBytes(AMessage, TEncoding.UTF8);

  PassedCount := 0;

  for Idx := 1 to AIterationCount do
  begin
    Logger.Append(Format('Count (%d)', [Idx]));

    LKeyPair := GenerateECKeyPair(AKeyType);
    Logger.Append(Format('%s ECKeyPair Generated Successfully.', [GetEnumName(TypeInfo(TKeyType), Ord(AKeyType))]));

    LPrivateKey := GetPrivateKey(LKeyPair);
    Logger.Append(Format('Private Key is %s', [ComputeBase16EncodeUpper(LPrivateKey)]));
    LPublicKeyXCoord := GetPublicKeyAffineX(LKeyPair);
    Logger.Append(Format('Public Key XCoord is %s', [ComputeBase16EncodeUpper(LPublicKeyXCoord)]));
    LPublicKeyYCoord := GetPublicKeyAffineY(LKeyPair);
    Logger.Append(Format('Public Key YCoord is %s', [ComputeBase16EncodeUpper(LPublicKeyYCoord)]));

    LPrivateKeyBigInteger := TBigInteger.Create(LPrivateKey);
    LPublicKeyXCoordBigInteger := TBigInteger.Create(LPublicKeyXCoord);
    LPublicKeyYCoordBigInteger := TBigInteger.Create(LPublicKeyYCoord);

    Logger.Append(Format('Private Key is %s and Sign is %s', [ComputeBase16EncodeUpper(LPrivateKeyBigInteger.ToByteArray()), GetSignAsString(LPrivateKeyBigInteger.SignValue)]));
    Logger.Append(Format('Public Key AffineX Coord is %s and Sign is %s', [ComputeBase16EncodeUpper(LPublicKeyXCoordBigInteger.ToByteArray()), GetSignAsString(LPublicKeyXCoordBigInteger.SignValue)]));
    Logger.Append(Format('Public Key AffineY Coord is %s and Sign is %s', [ComputeBase16EncodeUpper(LPublicKeyYCoordBigInteger.ToByteArray()), GetSignAsString(LPublicKeyYCoordBigInteger.SignValue)]));

    PrivateKeyRecreated := RecreatePrivateKeyFromByteArray(AKeyType, LPrivateKey);

    Logger.Append('Private Key Recreated.');

    PublicKeyRecreated := RecreatePublicKeyFromAffineXandAffineYCoord(AKeyType, LPublicKeyXCoord, LPublicKeyYCoord);

    Logger.Append('Public Key Recreated From AffineX and AffineY Coords.');

    LSig := DoECDSASign(PrivateKeyRecreated, LMessage);

    Logger.Append('Signature Generated Successfully.');

    Logger.Append(Format('R Sig is %s', [ComputeBase16EncodeUpper(LSig[0].ToByteArray())]));

    Logger.Append(Format('S Sig is %s', [ComputeBase16EncodeUpper(LSig[1].ToByteArray())]));

    PassVerify := DoECDSAVerify(PublicKeyRecreated, LMessage, LSig);

    if PassVerify then
    begin
      Logger.Append('Signature Verification Passed.');
      System.Inc(PassedCount);
    end
    else
      Logger.Append('Signature Verification Failed.');

  end;

  Logger.Append(Format('Passed %d out of %d Tests', [PassedCount, AIterationCount]));

  Logger.Append('================================================== END ===================================================');
end;

end.
