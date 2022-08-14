/*
    CBC-MAC.NET: A .NET implementation of length-prepend CBC-MAC.
    Copyright (c) 2022 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CBCMACDotNet;

public static class CbcMac
{
    public const int KeySize = 32;
    public const int TagSize = 16;
    private const int BlockSize = 16;
    private static readonly PaddingMode PaddingMode = PaddingMode.PKCS7;
    
    public static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        if (tag.Length != TagSize) { throw new ArgumentOutOfRangeException(nameof(tag), tag.Length, $"{nameof(tag)} must be {TagSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }
        Span<byte> plaintext = new byte[BlockSize + message.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(plaintext, (ulong)message.Length);
        message.CopyTo(plaintext[BlockSize..]);
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        ReadOnlySpan<byte> iv = stackalloc byte[BlockSize];
        Span<byte> ciphertext = new byte[aes.GetCiphertextLengthCbc(plaintext.Length, PaddingMode)];
        aes.EncryptCbc(plaintext, iv, ciphertext, PaddingMode);
        Span<byte> mac = ciphertext.Slice(ciphertext.Length - BlockSize, tag.Length);
        mac.CopyTo(tag);
        CryptographicOperations.ZeroMemory(ciphertext);
    }
    
    public static bool VerifyTag(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        if (tag.Length != TagSize) { throw new ArgumentOutOfRangeException(nameof(tag), tag.Length, $"{nameof(tag)} must be {TagSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }
        Span<byte> computedTag = stackalloc byte[tag.Length];
        ComputeTag(computedTag, message, key);
        bool valid = CryptographicOperations.FixedTimeEquals(tag, computedTag);
        CryptographicOperations.ZeroMemory(computedTag);
        return valid;
    }
}