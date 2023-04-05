# 关于
这是一个使用Go语言编写的一个IP端口扫描工具，可以批量扫描一个IP字典中的某一个端口是否开放，并且返回为一个txt文件，返回格式为[IP]:[Port]，如`127.0.0.1:80`。

如果论扫描速度的话，这个工具并不是最快的，仅仅是想在以后能够很方便的进行扫描操作，并且对数据进行处理，如扫描之后另作他用，这样自己写的工具反而更方便，可以调整保存的格式等。

这个项目开源，也完全是因为这一点。本人Golang学的并不怎么样，但是因为Python的性能问题，就没有使用Python，只好百来度去，然后花了几个小时的时间啃了一下go这门语言。
# 使用说明
## 1.默认配置：
### WIndows：
```
Pscan.exe -F <file name> -P <port number> -T <number of threads>
```
### Linux 或 Mac：
```
chmod +x Pscan
Pscan -F <file name> -P <port number> -T <number of threads>
```
**两者在使用方法上其实并异样，只是Windows系统中是有exe后缀的！**
## 2.参数
事实上，上面的默认配置只提供了filename、port、threads，也就是文件名、端口号、线程数，我们默认会保存到save.txt。
如果需要自定义，则需要根据下面的内容传参：
- IP字典文件
```bash
-F <文件名>
# 默认为ip.txt
```
- *端口号
```bash
-P <端口号>
```
- *线程数
```bash
-T <线程数>
```
- 输出文件
```bash
-O <输出文件名>
# 默认为save.txt
```
- 输出结果
```bash
-OF <输出结果类型，传True或False>
# 如果是True就输出开放的列表，如果是False就输出未开放的列表。默认是True。
```
- 超时时间
```bash
-timeout <Duration类型>
# 如2s是2秒，1s就是1秒，默认2秒。
```
# 其他
## 开源协议

本项目遵循MIT协议，项目被允许修改和共享，且允许商业使用，但需要保留LICENSE和相关版权。
如果你有更好的建议，倒不如提交一份issues：https://github.com/Moxin1044/Pscan/issues
## 知识许可证
<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="知识共享许可协议" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br /><span xmlns:dct="http://purl.org/dc/terms/" href="http://purl.org/dc/dcmitype/InteractiveResource" property="dct:title" rel="dct:type">Pscan</span> 由 <a xmlns:cc="http://creativecommons.org/ns#" href="https://github.com/Moxin1044/Pscan" property="cc:attributionName" rel="cc:attributionURL">末心</a> 采用 <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">知识共享 署名-相同方式共享 4.0 国际 许可协议</a>进行许可。<br />基于<a xmlns:dct="http://purl.org/dc/terms/" href="https://github.com/Moxin1044/Pscan" rel="dct:source">https://github.com/Moxin1044/Pscan</a>上的作品创作。
## 注意：
如果您Fork了项目，请注意不要修改LICENSE。