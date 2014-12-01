using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// Die Elementvorlage "Leere Seite" ist unter http://go.microsoft.com/fwlink/?LinkId=391641 dokumentiert.

namespace ShowCaseCrypto
{

    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();

            this.NavigationCacheMode = NavigationCacheMode.Required;
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            tbCipher.Text = "W1Qf0oMqlVGAqce81SBQ7A==";
            tbDecrypted.Text = DecodeAES(tbCipher.Text);
        }
    
        private readonly string AES_KEY = "AAAAAABBBBBBCCCCCCC";

        private string DecodeAES(string cipherText)
        {
            var pwBuffer = CryptographicBuffer.ConvertStringToBinary(AES_KEY, BinaryStringEncoding.Utf8);
            var cipherBuffer = CryptographicBuffer.ConvertStringToBinary(cipherText, BinaryStringEncoding.Utf8);

            KeyDerivationAlgorithmProvider keyDerivationProvider = KeyDerivationAlgorithmProvider.OpenAlgorithm("PBKDF2_SHA1");

            var name = SymmetricAlgorithmNames.AesCbcPkcs7;

            SymmetricKeyAlgorithmProvider symProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(name);
            
            CryptographicKey symmKey = symProvider.CreateSymmetricKey(pwBuffer);

            var resultBuffer = CryptographicEngine.Decrypt(symmKey, cipherBuffer, null);
            string result = CryptographicBuffer.ConvertBinaryToString(BinaryStringEncoding.Utf16LE, resultBuffer);

            return result;
        }
    }
}
