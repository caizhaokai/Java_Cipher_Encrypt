# Java_Cipher_Encrypt
Java原生加密，使用Cipher类进行加密
====
一、Java的Cipher类
----
#1.1 Cipher类提供了加密和解密的功能。该项目使用Cipher类完成aes，des，des3和rsa加密.  
获取Cipher类的对象：Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding"); 参数按"算法/模式/填充模式"，有以下的参数  
* AES/CBC/NoPadding (128)  
* AES/CBC/PKCS5Padding (128)  
* AES/ECB/NoPadding (128)  
* AES/ECB/PKCS5Padding (128)  
* DES/CBC/NoPadding (56)  
* DES/CBC/PKCS5Padding (56)  
* DES/ECB/NoPadding (56)  
* DES/ECB/PKCS5Padding (56)  
* DESede/CBC/NoPadding (168)  
* DESede/CBC/PKCS5Padding (168)  
* DESede/ECB/NoPadding (168)  
* DESede/ECB/PKCS5Padding (168)  
* RSA/ECB/PKCS1Padding (1024, 2048)  
* RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)  
* RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)  
>>(1)加密算法有：AES，DES，DESede(DES3)和RSA 四种  
>>(2) 模式有CBC(有向量模式)和ECB(无向量模式)，向量模式可以简单理解为偏移量，使用CBC模式需要定义一个IvParameterSpec对象  
>>(3) 填充模式: 
>>>>>>NoPadding: 加密内容不足8位用0补足8位, Cipher类不提供补位功能，需自己实现代码给加密内容添加0, 如{65,65,65,0,0,0,0,0}  
>>>>>>PKCS5Padding: 加密内容不足8位用余位数补足8位, 如{65,65,65,5,5,5,5,5}或{97,97,97,97,97,97,2,2}; 刚好8位补8位8  
#1.2 Cipher对象需要初始化，init(int opmode, Key key, AlgorithmParameterSpec params)  
>>cipher.init(Cipher.ENCRYPT_MODE, key, [iv])  
>>(1)opmode param：Cipher.ENCRYPT_MODE(加密模式)和 Cipher.DECRYPT_MODE(解密模式)  
>>(2)key param：密匙，使用传入的盐构造出一个密匙，可以使用SecretKeySpec、KeyGenerator和KeyPairGenerator创建密匙，其中  
>>>>>>>>SecretKeySpec和KeyGenerator支持AES，DES，DESede三种加密算法创建密匙  
>>>>>>>>KeyPairGenerator支持RSA加密算法创建密匙  
>>(3)iv param：使用CBC模式时必须传入该参数，该项目使用IvParameterSpec创建iv 对象  
#1.3 加密或解密 byte[] b = cipher.doFinal(content);  
>>返回结果为byte数组，如果直接使用 new String(b) 封装成字符串，则会出现乱码  

二、对加密结果进行一层包装
----
    2.1、针对1.3返回结果返回字符串乱码的问题，一般对byte数组进行处理，有两种处理方式：转换为base64的字符串或转换为16进制的字符串
    2.2、转换为base64
        使用apache下的Base64类进行封装即可，Base64.encodeBase64String(result); 结果形如 qPba5V+b0Ox3Um...
        <dependency>
            <groupId>commons-codec</groupId>
            <artifactId>commons-codec</artifactId>
            <version>???</version>
        </dependency>
    2.3、转换为16进制
       编码实现，即编码实现将2进制转换为16进制，可参看代码中的HexUtil.java文件，结果形如 04A2784A45234B.....

三、一个简单加密，解密实现
----
    3.1 加密
    public String encrypt(String content, String slatKey, String vectorKey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKey secretKey = new SecretKeySpec(slatKey.getBytes(), "AES");
		IvParameterSpec iv = new IvParameterSpec(vectorKey.getBytes());
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
		byte[] encrypted = cipher.doFinal(content.getBytes());
		return Base64.encodeBase64String(encrypted);
	}
    3.2 解密
    public String decrypt(String base64Content, String slatKey, String vectorKey) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKey secretKey = new SecretKeySpec(slatKey.getBytes(), "AES");
		IvParameterSpec iv = new IvParameterSpec(vectorKey.getBytes());
		cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
		byte[] content = Base64.decodeBase64(base64Content);
		byte[] encrypted = cipher.doFinal(content);
		return new String(encrypted);
	}
    
    
