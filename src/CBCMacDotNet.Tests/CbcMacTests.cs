using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CBCMACDotNet;

namespace CBCMacDotNet.Tests;

[TestClass]
public class CbcMacTests
{
    private static readonly byte[] Tag = Convert.FromHexString("a51d7ed83b9e4037cf8da336f7a46881");
    private static readonly byte[] Message = Encoding.UTF8.GetBytes("Fool of a Took!");
    private static readonly byte[] Key = Convert.FromHexString("dc1dcb9b0073a0e06dd2e04ad31d434f91cef039925218fe99d09311f4c1773f");
    
    [TestMethod]
    public void ComputeTag_ValidInputs()
    {
        Span<byte> tag = stackalloc byte[CbcMac.TagSize];
        CbcMac.ComputeTag(tag, Message, Key);
        Assert.IsTrue(tag.SequenceEqual(Tag));
    }
    
    [TestMethod]
    public void ComputeTag_DifferentMessage()
    {
        Span<byte> tag = stackalloc byte[CbcMac.TagSize];
        Span<byte> message = Message.ToArray();
        message[0]++;
        CbcMac.ComputeTag(tag, message, Key);
        Assert.IsFalse(tag.SequenceEqual(Tag));
    }
    
    [TestMethod]
    public void ComputeTag_DifferentKey()
    {
        Span<byte> tag = stackalloc byte[CbcMac.TagSize];
        Span<byte> key = Key.ToArray();
        key[0]++;
        CbcMac.ComputeTag(tag, Message, key);
        Assert.IsFalse(tag.SequenceEqual(Tag));
    }
    
    [TestMethod]
    public void VerifyTag_ValidInputs()
    {
        bool valid = CbcMac.VerifyTag(Tag, Message, Key);
        Assert.IsTrue(valid);
    }
    
    [TestMethod]
    public void VerifyTag_DifferentTag()
    {
        Span<byte> tag = Tag.ToArray();
        tag[0]++;
        bool valid = CbcMac.VerifyTag(tag, Message, Key);
        Assert.IsFalse(valid);
    }
    
    [TestMethod]
    public void VerifyTag_DifferentMessage()
    {
        Span<byte> message = Message.ToArray();
        message[0]++;
        bool valid = CbcMac.VerifyTag(Tag, message, Key);
        Assert.IsFalse(valid);
    }
    
    [TestMethod]
    public void VerifyTag_DifferentKey()
    {
        Span<byte> key = Key.ToArray();
        key[0]++;
        bool valid = CbcMac.VerifyTag(Tag, Message, key);
        Assert.IsFalse(valid);
    }
}