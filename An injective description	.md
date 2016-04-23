## An injective description	 

### 	对一个现存的且不清楚内部源代码的可执行文件注入修改文件后，让可执行文件除了执行原有程序之后还能输出指定的字符串到当前目录的一个文件下.具体操作要求是写一个注入程序，能够自己识别elf文件头的相关节头部表的地址信息，同时开辟另外一片内存空间并记录两者的相对偏移地址，并修改文件的部分引用，当elf可执行目标文件运行时能够通过elf重定位从原程序地址跳转到另外一个注入程序的头地址，当注入文件执行完毕后，跳转回原程序地址使之能够正确运行，同时产生注入程序的运行结果。

##### to inject a excutable file into a existing linking and excutable file,ensuring that original file can output a new .txt which is excuted by the injective objective file and then it can work properly as it used to be like.