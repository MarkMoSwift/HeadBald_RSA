#coding=utf-8
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import tkinter.filedialog
import tkinter as tk
import tkinter.messagebox
import os, shutil, base64, pickle, clipboard
from shutil import copyfile
from PIL import ImageTk, Image

global basePath
global publicKeyList
global keyNameList
global checkTextList
global main_box

noMyKey = '你还没有自己的密钥，如果没有自己的密钥，别人就无法向你发送文件。\n是否要生成自己的密钥？'
keyLen = 2048
version = "1.6"
verExplainList = ["1.修复了不生成自己密钥时无法导入他人密钥的问题",
                  "2.修复了错用私钥解密的问题",
                  "3.修复了不选文件仍然显示加密解密成功的问题"]
code = "nooneknows"

#代码来源：https://maoao530.github.io/2016/11/20/python-rsa/
#我的和别人的公钥存储在 basePath + '/' + 'my_rsa_public.pem'

def CreateRSAKeys():
    global publicKeyList
    global keyNameList
    global checkTextList
    global code
    if code == "":
        setCode()
    code = 'nooneknows'
    key = RSA.generate(keyLen)
    encrypted_key = key.exportKey(passphrase = code, pkcs = 8, protection = "scryptAndAES128-CBC")
    # 私钥
    with open(basePath + '/' + 'my_private_rsa_key.bin', 'wb') as f:
        f.write(encrypted_key)
    # 公钥
    publickey_r = key.publickey().exportKey()
    publickey_s = publickey_r.decode('utf-8')
    publicKeyList[0] = publickey_r
    with open(basePath + '/' + 'my_rsa_public.pem', 'wb') as f:
        f.write(publickey_r)
    
    with open(basePath + '/' + 'usr_info.pickle', 'wb') as usr_file:
        pickle.dump([basePath, publicKeyList, keyNameList], usr_file)
    checkTextList[0].set("自己  " + shortPublicKey(publicKeyList[0]))
    msg = "公钥保存在文件 my_rsa_public.pem 中\n" + publickey_s + "\n是否要复制公钥？"
    choice = tk.messagebox.askquestion(title = '密钥已生成！', message = msg)   # return 'yes' , 'no'
    if choice == 'yes':
        copyMyPublicKey()

def Encrypt(filePath, publicKey):         
    data = ''
    with open(filePath, 'rb') as f:
        data = f.read()
    with open(filePath, 'wb') as out_file:
        # 收件人秘钥 - 公钥
        recipient_key = RSA.import_key(publicKey)
        session_key = get_random_bytes(16)
        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        out_file.write(cipher_rsa.encrypt(session_key))
        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        out_file.write(cipher_aes.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)
        
def Descrypt(filename):
    global code
    if code == "":
        getCode()
    with open(filename, 'rb') as fobj:
        private_key = RSA.import_key(open(basePath + '/' + 'my_private_rsa_key.bin').read(),
                                    passphrase=code)
        enc_session_key, nonce, tag, ciphertext = [ fobj.read(x) 
                                                    for x in (private_key.size_in_bytes(), 
                                                    16, 16, -1) ]
        cipher_rsa = PKCS1_OAEP.new(private_key)
        try:
            session_key = cipher_rsa.decrypt(enc_session_key)
        except:
            tk.messagebox.showerror(title='Error', message='发生了一个错误！\n可能是因为你用了一个错误的密钥来解密。')
            return 1 #表示发生了错误
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    with open(filename, 'wb') as wobj:
        wobj.write(data) 

    return 0

def RenameFile(dir,filename):
    filename_bytes = filename.encode('utf-8')
    filename_bytes_base64 = base64.encodebytes(filename_bytes)
    filename_bytes_base64 = filename_bytes_base64[::-1][1:]
    new_filename = (filename_bytes_base64.decode('utf-8').replace("\n","-")).replace("/","_") + ".crypt1"
    msg = filename + " -> " + new_filename
    try:
        os.rename(os.path.join(dir, filename), os.path.join(dir,new_filename))
    except:
        os.remove(os.path.join(dir,new_filename))
        os.rename(os.path.join(dir, filename), os.path.join(dir,new_filename))
    return msg
    

def ReserveFilename(dir, filename):
    f = filename
    filename = filename[::-1][7:][::-1]
    filename_base64 = filename[::-1] + '\n'
    filename_bytes_base64 = filename_base64.replace("-","\n").replace("_","/").encode('utf-8')
    ori_filename = base64.decodebytes(filename_bytes_base64).decode('utf-8')
    msg = f + " -> " + ori_filename
    os.rename(os.path.join(dir, f),os.path.join(dir,ori_filename))
    return msg
    
def selectFile():
    #选择文件path_接收文件地址
    pathTuple = tkinter.filedialog.askopenfilename(title="Select file", multiple = True)
    #path设置path_的值
    pathList = ''
    for path_ in pathTuple:
        path_ = path_ + ';'
        pathList += path_
    filePath.set(pathList)
    return pathTuple

def selectFolder(selectPath):
    # 文件夹选择
    selected_folder = tkinter.filedialog.askdirectory()  # 使用askdirectory函数选择文件夹
    selectPath.set(selected_folder)
    return selectPath

def getFileLists(file_dir='.'):
    list_directory = os.listdir(file_dir)
    filelists = []
    for directory in list_directory:
        if(os.path.isfile(file_dir + "/" + directory)):
            filelists.append(directory)
    return filelists

def EncryptGroup():
    pathTup = selectFile()
    renameList = []
    if pathTup != "":
        msg = "文件加密："
        #这个列表记录了需要发送给的人
        usrList = []
        for i in range(0,len(keyNameList)):
            #查看哪些公钥被选中了
            if checkVarList[i].get():
                usrList.append(keyNameList[i])
        for usr in usrList:
            targetRoot = basePath + '/' + usr + ' - 加密'
            if not os.path.exists(targetRoot): #判断所在目录下是否有该文件名的文件夹
                #新建一个文件夹，名字叫做“某某人 - 加密”，用来存放加密给他的文件
                os.mkdir(targetRoot)
            msg += '\n' + '----------' + usr + '----------'
            #遍历每一个选中的需要加密的文件
            for sourcePath in pathTup:
                filename = sourcePath.split("/")[-1]
                sourceRoot = sourcePath.split(filename)[0]
                copyfile(sourcePath, targetRoot + '/' + filename)
                Encrypt(targetRoot + '/' + filename, publicKeyList[keyNameList.index(usr)])
                msg += '\n' + RenameFile(targetRoot, filename)
        tk.messagebox.showinfo(title='加密成功', message = msg)   # return 'ok'
    else:
        tk.messagebox.showwarning(title='Warning', message='你还没有选择文件！')

def DecryptGroup():
    pathTup = selectFile()
    reserveList = []
    decryptNum = 0
    decryptFailNum = 0
    if pathTup != () and pathTup != "":
        msg = "文件解密："
        targetRoot = basePath + '/解密'
        if not os.path.exists(targetRoot): #判断所在目录下是否有该文件名的文件夹
            os.mkdir(targetRoot)
        msg += '\n' + '----------解密成功----------'
        #遍历每一个选中的需要解密的文件
        for sourcePath in pathTup:
            filename = sourcePath.split("/")[-1]
            sourceRoot = sourcePath.split(filename)[0]
            copyfile(sourcePath, targetRoot + '/' + filename)
            if Descrypt(targetRoot + '/' + filename) == 0:
                msg += '\n' + ReserveFilename(targetRoot, filename)
                decryptNum += 1
            else:
                decryptFailNum += 1
                if decryptFailNum == 3:
                    choice = tk.messagebox.askyesno(title='Error', message='到目前为止已经有3个文件解密失败，是否还要继续解密剩下的文件？')
                    if choice == False:
                        break
        if decryptNum > 0:
            tk.messagebox.showinfo(title='解密成功', message = msg)   # return 'ok'
        else:
            tk.messagebox.showinfo(title='解密失败', message = '没有文件被成功解密！')
    else:
        tk.messagebox.showwarning(title='Warning', message = '你还没有选择文件！')

def detectKey():
    if os.path.isdir(basePath) == 0:
        return 4; #没有根目录

    isMyKey = os.path.isfile(basePath + '/' + 'my_private_rsa_key.bin')
    isUsrInfo = os.path.isfile(basePath + '/' + 'usr_info.pickle')
    
    if isMyKey and isUsrInfo:
        flag = 0
    elif isMyKey and isUsrInfo  == 0:
        flag = 1 #有私钥但无文件打包
    elif isMyKey == 0 and isUsrInfo:
        flag = 2 #有别人的公钥但无自己的密钥
        #choice = tk.messagebox.askyesno(title = 'Warning', message = noMyKey)
        #if choice:
            #CreateRSAKeys()
    else:
        flag = 3 #
    return flag

def copyMyPublicKey():
    global publicKeyList
    if detectKey():
        choice = tk.messagebox.askyesno(title = 'Warning', message = noMyKey)
        if choice:
            CreateRSAKeys()
        else:
            clipboard.copy("你还没有自己的公钥")
    else:
        clipboard.copy(publicKeyList[0].decode('utf-8'))

def createImportWindow():
    global publicKeyList
    global keyNum
    #导入新公钥
    def importPublicKey():
        publicKey_s = textPublicKey.get("1.0","end")
        publicKey_r = publicKey_s.encode('utf-8')
        keyName = entryUsrComment.get()
        keyNum = len(publicKeyList)
        #加入公钥
        publicKeyList.append(publicKey_r)
        #加入公钥的名字
        keyNameList.append(keyName)
        
        #新建一个多选框
        checkVarList.append(tk.IntVar())
        checkTextList.append(tk.StringVar())#字符串变量
        checkTextList[keyNum].set(keyName + '  ' + shortPublicKey(publicKeyList[keyNum]))
        checkList.append( tk.Checkbutton(main_box, textvariable = checkTextList[keyNum], 
                                     variable = checkVarList[keyNum], onvalue = 1, offvalue=0) )
        checkList[keyNum].place(x = 10, y = 40 + 30 * keyNum)
        #保存他人的数据
        with open(basePath + '/' + 'usr_info.pickle', 'wb') as usr_file:
            pickle.dump([basePath, publicKeyList, keyNameList], usr_file)
        keyNum += 1
        importWindow.destroy()
    importWindow = tk.Toplevel(main_box)
    importWindow.title("导入他人公钥")
    importWindow.geometry('400x200')

    varUsrComment = tk.StringVar()
    varPublicKey = tk.StringVar()
    #他的名字的示例
    varUsrComment.set("小熊维尼")
    #公钥格式的示例
    varPublicKey.set("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----")

    labelUsrComment = tk.Label(importWindow, text = "他人名字：")
    entryUsrComment = tk.Entry(importWindow, textvariable = varUsrComment)
    labelPublicKey = tk.Label(importWindow, text = "他人公钥：")
    textPublicKey = tk.Text(importWindow, height = 5)
    buttonImport = tk.Button(importWindow, text = "导入", command = importPublicKey)
    
    labelUsrComment.grid(row=0, column=0)
    entryUsrComment.grid(row=0, column=1)
    labelPublicKey.grid(row=1, column=0)
    textPublicKey.insert("insert", varPublicKey.get())
    buttonImport.grid(row=2, column=0)
    textPublicKey.grid(row=1, column=1)

#更换用户路径
def changePath():
    global basePath
    global publicKeyList
    global checkTextList
    global keyNameList
    selectPath = tk.StringVar()
    basePath = selectFolder(selectPath).get()
    #每一次更换用户路径，都要检查是否已经存在数据
    if detectKey() == 0:
        #导入密钥和用户数据，并做修改
        with open(basePath + '/' + 'usr_info.pickle', 'rb') as usrFile:
            # usrData = [用户路径, 公钥列表, 公钥备注]
            usrData = pickle.load(usrFile)
            usrData[0] = basePath
            publicKeyList = usrData[1]
            keyNameList = usrData[2]
        #保存用户数据
        with open(basePath + '/' + 'usr_info.pickle', 'wb') as usrFile:
            pickle.dump(usrData, usrFile)
        checkTextList[0].set("自己    " + shortPublicKey(publicKeyList[0]))

        #显示其他人的公钥
        for i in range(0,len(publicKeyList)):
            checkVarList.append(tk.IntVar())
            checkTextList.append(tk.StringVar())#字符串变量
            checkTextList[i].set(keyNameList[i] + '  ' + shortPublicKey(publicKeyList[i]))
            checkList.append( tk.Checkbutton(main_box, textvariable = checkTextList[i], 
                                            variable = checkVarList[i], onvalue = 1, offvalue=0) )
            checkList[i].place(x = 10, y = 40 + 30 * i)

    
def shortPublicKey(publicKey_r):
    global keyLen
    publicKey_s = publicKey_r.decode('utf-8')
    shortKey = publicKey_s[27:32] + '...' + publicKey_s[int(keyLen / 8):int(keyLen / 8 + 10)] + '...'
    return shortKey


def closeCodeWindow():
    pass


def setCode():
    codeWindow = tk.Toplevel(main_box)
    codeWindow.title("请设置密码")
    codeWindow.geometry()

    varCode = tk.StringVar()
    varRepeatCode = tk.StringVar()

    labelEnterCode = tk.Label(importWindow, text = "输入密码：")
    labelRepeatCode = tk.Label(importWindow, text = "重复密码：")
    entryCode = tk.Entry(codeWindow, textvariable = varCode, show = "*")
    buttonConfirm = tk.Button(codeWindow, text = "确定", command = closeCodeWindow)
    entryRepeatCode = tk.Entry(codeWindow, textvariable = varRepeatCode, show = "*")

    labelEnterCode.grid(row = 0, column = 0)
    entryCode.grid(row = 0, column = 1)
    labelRepeatCode.grid(row = 1, column = 0)
    entryRepeatCode.grid(row = 1, column = 1)
    buttonConfirm.grid(row = 1, column = 2)
    code = ""

def getCode():
    codeWindow = tk.Toplevel(main_box)
    codeWindow.title("请输入密码")
    codeWindow.geometry()
    code = ""

def changeCode():
    codeWindow = tk.Toplevel(main_box)
    codeWindow.title("请修改密码")
    codeWindow.geometry()
    code = ""

def lockPrivateKey():
    pass

def showVersion():
    msg = "修复问题：\n"
    for verEplanation in verExplainList:
        msg += verEplanation + "\n"
    tk.messagebox.showinfo(title = '版本说明', message = msg)

if __name__ == '__main__':
    basePath = os.getcwd().replace('\\','/')
    
    publicKeyList = [b'']
    keyNameList = ["自己"]

    main_box = tk.Tk()
    main_box.title("脑袋光光加密器")
    main_box.geometry('400x400')

    #多选项
    checkList = []
    #多选项的值
    checkVarList = []
    #多选项的文本
    checkTextList = []
    checkVarList.append(tk.IntVar())
    checkTextList.append(tk.StringVar())#字符串变量
    
    # welcome image
    # 画布
    '''
    canvas = tk.Canvas(main_box, width=400, height=400, bd=0, highlightthickness=0)
    img = Image.open('03.gif')
    photo = ImageTk.PhotoImage(img)
    canvas.create_image(70, 0, anchor='nw', image = photo)
    canvas.pack()
    '''

    #变量filePath 需要加密或者解密的文件
    filePath = tk.StringVar()
    #输入框，标记，按键
    tk.Label(main_box,text = "目标路径:").place(x = 0, y = 10)
    #输入框绑定变量filePath
    tk.Entry(main_box, textvariable = filePath).place(x = 60, y = 10)
    tk.Button(main_box, text = "加密文件", command = EncryptGroup).place(x = 215, y = 6)
    tk.Button(main_box, text = "生成密钥", command = CreateRSAKeys).place(x = 290, y = 36)
    tk.Button(main_box, text = "解密文件", command = DecryptGroup).place(x = 290, y = 6)
    tk.Button(main_box, text = "复制我的公钥", command = copyMyPublicKey).place(x = 276, y = 66)
    tk.Button(main_box, text = "导入他人公钥", command = createImportWindow).place(x = 276, y = 96)
    tk.Button(main_box, text = "改变用户目录", command = changePath).place(x = 276, y = 126)
    tk.Button(main_box, text = "锁定私钥", command = changeCode).place(x = 290, y = 156) #lockPrivateKey
    tk.Button(main_box, text = "修改密码", command = changeCode).place(x = 290, y = 186)
    tk.Button(main_box, text = "Version " + version, command = showVersion).place(x = 276, y = 370)

    #不存在用户目录，需要新建
    if os.path.isdir(basePath)  == 0:
        choice = tk.messagebox.askquestion(title = 'Warning', 
                                  message = "你还没有设置用户文件夹。是否要设置？")
        if choice == 'yes':
            changePath()
        else:
            pass
    #存在用户目录
    else:
        #存在公钥和用户文件
        if detectKey() == 0:
            with open(basePath + '/' + 'usr_info.pickle', 'rb') as usrFile:
                usrData = pickle.load(usrFile)
                publicKeyList = usrData[1]
                keyNameList = usrData[2]

            #显示自己的公钥
            checkTextList[0].set("自己  " + shortPublicKey(publicKeyList[0]))
            # 勾选赋值为1，不勾选赋值为0
            checkList.append( tk.Checkbutton(main_box, textvariable = checkTextList[0], 
                                     variable = checkVarList[0], onvalue = 1, offvalue=0) )

            checkList[0].place(x = 10, y = 40)
            #显示其他人的公钥
            for i in range(1,len(publicKeyList)):
                checkVarList.append(tk.IntVar())
                checkTextList.append(tk.StringVar())#字符串变量
                checkTextList[i].set(keyNameList[i] + '  ' + shortPublicKey(publicKeyList[i]))
                checkList.append( tk.Checkbutton(main_box, textvariable = checkTextList[i], 
                                             variable = checkVarList[i], onvalue = 1, offvalue=0) )
                checkList[i].place(x = 10, y = 40 + 30 * i)
        #不存在
        else:
            #显示自己的公钥
            checkTextList[0].set("自己  " + "你还没有生成密钥")
            # 勾选赋值为1，不勾选赋值为0
            checkList.append( tk.Checkbutton(main_box, textvariable = checkTextList[0], 
                                     variable = checkVarList[0], onvalue = 1, offvalue=0) )

            checkList[0].place(x = 10, y = 40)
    
    main_box.mainloop()
    
