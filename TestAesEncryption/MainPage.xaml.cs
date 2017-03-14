using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using System.Text;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace TestAesEncryption
{    
    public class AesEnDecryption
    {
        private IBuffer m_iv = null;
        private CryptographicKey m_key;
        private string base64Key;
        private string base64IV;

        public AesEnDecryption(string hexKey, string hexIV)
        {
            // Key with 256 and IV with 16 length
            base64Key = Convert.ToBase64String(ConvertFromStringToHex(hexKey)); // "KA+LuMQ9Uy84nvDipTISILB4KwZSBdzfy42PAu1RFbk="
            base64IV = Convert.ToBase64String(ConvertFromStringToHex(hexIV));   // "zAppd54VeAra5GxF60UaIw==";

            IBuffer key = Convert.FromBase64String(base64Key).AsBuffer();
            m_iv = Convert.FromBase64String(base64IV).AsBuffer();
            SymmetricKeyAlgorithmProvider provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            m_key = provider.CreateSymmetricKey(key);
        }

        public string Encrypt(string data)
        {
            byte[] dataBytes = Encoding.ASCII.GetBytes(data);

            IBuffer bufferMsg = CryptographicBuffer.ConvertStringToBinary(Encoding.ASCII.GetString(dataBytes), BinaryStringEncoding.Utf8);
            IBuffer bufferEncrypt = CryptographicEngine.Encrypt(m_key, bufferMsg, m_iv);
            byte[] encryptedBytes = bufferEncrypt.ToArray();
            string result = Convert.ToBase64String(encryptedBytes);
            return result;
        }

        public string Decrypt(string cipherText)
        {
            byte[] dataBytes = Convert.FromBase64String(cipherText);

            IBuffer bufferDecrypt = CryptographicEngine.Decrypt(m_key, dataBytes.AsBuffer(), m_iv);
            byte[] decryptedBytes = bufferDecrypt.ToArray();
            string result = Encoding.UTF8.GetString(decryptedBytes);
            return result;
        }

        public static byte[] ConvertFromStringToHex(string inputHex)
        {
            inputHex = inputHex.Replace("-", "");

            byte[] resultantArray = new byte[inputHex.Length / 2];
            for (int i = 0; i < resultantArray.Length; i++)
            {
                resultantArray[i] = Convert.ToByte(inputHex.Substring(i * 2, 2), 16);
            }
            return resultantArray;
        }
    }

    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            AesEnDecryption en = new AesEnDecryption("280f8bb8c43d532f389ef0e2a5321220b0782b065205dcdfcb8d8f02ed5115b9", "CC0A69779E15780ADAE46C45EB451A23");
            EncryptedTextTextBox.Text = en.Encrypt(OriginalTextTextBox.Text);
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            AesEnDecryption en = new AesEnDecryption("280f8bb8c43d532f389ef0e2a5321220b0782b065205dcdfcb8d8f02ed5115b9", "CC0A69779E15780ADAE46C45EB451A23");
            DecryptedTextTextBox.Text = en.Decrypt(EncryptedTextTextBox.Text);
        }
    }
}
