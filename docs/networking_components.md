# A deeper dive into WeChat networking components

In this section, we provide additional details about WeChat’s networking components. For us to research WeChat’s networking cryptography, we had to first understand its system architecture surrounding networking. Here we document our understanding, which we believe to be useful for other researchers on a similar topic.

At a high level, we can categorize WeChat Networking Components into two layers. The Inner Layer consists mainly of the “Scene Classes” and “RR Classes” and is written in Java. Other app components call the Inner Layer when they want to start a network request. The Inner Layer is in charge of serialization, which is a process to turn in-memory request objects into chunks of data that can be passed into the Business-layer Encryption. An older implementation of encryption called the Business-layer Encryption is handled in this layer. The output (ciphertext) is passed to the Outer Layer. The Outer Layer consists mainly of the “STN” module and is written in C++. The STN module in WeChat is highly similar to the open source STN module from Mars. WeChat’s STN primarily adds code to implement MMTLS Encryption.

In the remainder of this section, we show how WeChat’s Networking Components handle network communication requests, starting from where other components call into Networking Components up until the prepared data is passed to the operating system for transmission. While we discuss how WeChat sends data to WeChat’s servers, we do not explicitly discuss how WeChat receives data from those servers. However, the process is generally the same except in reverse.

### WeChat request types

In the WeChat app, each API is represented in the Java code as a combination of one ***Scene Class*** and one ***RR Class***. There are many server APIs that a client can call over the network to achieve different functionalities. We have counted 125 unique APIs, with more uncounted. Each API is identified by a unique internal URI (usually starting with “/cgi-bin”) and a “request type” number (an approximately 2–4 digit integer). To invoke an API, the client needs to fill in data fields specific to that API in a “WeChat Request”, serialize it, encrypt it, then finally send it to the server.

For Scene Classes, we call them as such because the names of these classes usually start with “NetScene”, and that they all inherit from the common base class “`NetSceneBase`” (a Java abstract class). If a component in WeChat wishes to interact with the API, it can simply call into the corresponding scene class. Scene classes could roughly be seen as “controllers” from the [MVC model](https://en.wikipedia.org/wiki/Model%E2%80%93view%E2%80%93controller) because they operate on the data that is about to be sent.

In `NetSceneBase`, there are two important functions: `dispatch()` and `doScene()`.

![dispatch Screenshot_20231225_150555](https://github.com/user-attachments/assets/e3c67864-ae07-4872-8286-7875d0cd0bd9)


The `dispatch()` function is responsible for performing a series of checks, before dispatching the request to lower-level components including `NetworkConnectionInterface`, `RDispatcher`, `MMAutoAuth`, `MMNativeNetTaskAdapter,` and `STNLogic`. Then `STNLogic` would finally turn the request into a “task” to be handled by the *STN Task Manager*.

The `doScene()` function is set as an abstract function, which means that each class that is derived from `NetSceneBase` will provide its own implementation. This makes sense because for each API, different preparations are needed to send the request. The `doScene()` functions in Scene Classes are also responsible for calling the `dispatch()` function once the request is fully prepared. Here, we take `NetSceneReg` as an example for us to illustrate. `NetSceneReg` is a Scene Class tied to one of the APIs that performs user account registration.

![NetSceneReg Screenshot_20231225_152533](https://github.com/user-attachments/assets/749a6bf6-4b0c-4281-89e1-2fa9ad17dd12)


From the source code we can see that various data fields needed for user account registration are passed into NetSceneReg during its [instantiation](https://en.wikipedia.org/wiki/Instance\_(computer\_science)). We also notice that `NetSceneReg.getType()` returns 126\. This is the “request type” number we mentioned earlier.

`NetSceneReg.doScene()` is relatively simple, it contains mostly just a simple call to `NetSceneBase.dispatch()`:  

![doScene Screenshot_20231226_142921](https://github.com/user-attachments/assets/62fd86cc-cb6c-4541-a087-f48915c8d8a8)


The class corresponding to this account registration API is `MMReqRespReg2`. We call these RR Classes because they usually have the string “ReqResp” in their names. All RR Classes are derived from the abstract class `ReqRespBase`. A RR class also implements the `getUri()` function, which is the unique internal URI for the server API we mentioned earlier.  
![MMReqRespReg2 Screenshot_20231226_144917](https://github.com/user-attachments/assets/989cdafa-9c88-41b1-8b6a-5615b9dd37c3)

*RR objects* instantiated from RR Classes hold the `reqobj` and `respobj` objects, which represents the request data and response data specific to the API and can be seen as a “model” object in the sense of MVC model. In our example, `reqobj` is of type `MMReg2.Req`, which is derived from the type `MMBase.Req`. `MMReg2.Req` defines the data fields of this request type, and also implements the `toProtoBuf()` function. `toProfoBuf()` converts the request object (containing the request data fields) in the runtime memory into a byte array using the [Protocol Buffers](https://protobuf.dev/) (Protobuf) format. However, `toProtoBuf()` would only be called at a later stage (Req2Buf stage) instead of the current stage.

Continuing in our example, `MobileLoginOrForceReg` is one of the locations that invoke the NetSceneReg API. `MobileLoginOrForceReg` is a User Interface class. It is derived from Android’s [AppCompatActivity](https://developer.android.com/reference/androidx/appcompat/app/AppCompatActivity) class, which represents an interface for a user to carry out an “[activity](https://developer.android.com/guide/components/activities/intro-activities)” in an app. NetSceneReg is invoked in `MobileLoginOrForceReg.sendRequest()` like this:  
![sendRequest Screenshot_20240801_171542](https://github.com/user-attachments/assets/1fcac61e-fc4e-48cb-adcd-7dec0ecabae1)


`MobileLoginOrForceReg.sendRequest()` shows a typical example of how Scene Classes are invoked. They are put into a “NetSceneQueue” instance by `NetSceneQueue.checkAndRun()`. (Note: even though NetSceneQueue contains “NetScene” in its name, it is not a Scene Class.) By searching for usage locations of `checkAndRun()`, Jadx can find a total of 1881 locations. These are all locations where a server API is invoked, using different Scene Classes.  
![checkAndRun Screenshot_20240801_171732](https://github.com/user-attachments/assets/79341c54-bc8b-49b8-a315-8a90bef15d8f)


Based on our high level reading of `NetSceneQueue` code, it seems to be responsible for managing the queueing of different server API calls. It also reacts to a few operating system events such as when the app is being put into the background or foreground.

`NetSceneQueue.checkAndRun()` calls `NetSceneQueue.doSceneImp()`, which then calls the `doScene()` function in Scene Classes that it is working with at the time.

On a side note, Scene Classes usually also implement the `onGYNetEnd()` function. This function is a callback function that gets called after the underlying layers have decrypted and deserialized the API response from the server. `onGYNetEnd()` implements the actions to be taken after receiving the server response, for example saving the server-returned data into local databases.

So far, we have explained the various abstractions to provide WeChat app components easy access to WeChat’s server APIs. We summarize shortly as below:

* Scene Classes: They are there for other components to call to start an API request. Each server API has its corresponding Scene Class.  
* RR Classes: They define the data fields of the request and response of a server API. Each server API has its corresponding RR Class.

### WeChat’s network connection manager

A component internally called “STN”, a networking component from Mars, serves as WeChat’s network connection manager. As mentioned briefly in the previous section, `NetSceneBase.dispatch()` will construct a “task” to submit it to STN. A “task” in STN is an abstraction of a network connection. MMTLS utilizes two types of transport protocol, Longlink and Shortlink. Longlink is an abstraction of a long-lived TCP connection. Shortlink is an HTTP request and response, where after the response is received the connection is closed. We will discuss more about Longlink and Shortlink in later sections.

Up until this point, the networking code that we have described has all been running on the “main” process. However, STN runs on a different process called “:push”. To send the request related objects from the “main” process to the “:push” process, the “main” process communicates with the “:push” process using IPC (inter-process communication) via Android’s [AIDL](https://source.android.com/docs/core/architecture/aidl) feature. From this point on, the code that we describe runs in the “:push” process.

In the “:push” process, `MMAutoAuth` is invoked. It reads the logged-in user session data to construct an `AccInfo` object (likely an abbreviation of “account information”). It then calls `MMNativeNetTaskAdapter.startTask()` with the request object and `AccInfo` object. From what we can understand from the code, “AutoAuth” refers to an authentication mechanism, where the user has previously completed the log-in process, and has some session data stored on the device. Using AutoAuth, the server knows that a particular network request is sent by the logged-in user. In contrast, the term “ManualAuth” in WeChat refers to another authentication mechanism, where the user logs in to the account using phone numbers and passwords or other credentials.

In `MMNativeNetTaskAdapter.startTask()` , a new `StnLogic.Task()` object is created, and `startTask()` is called on that object. `STNLogic` is a Java wrapper class for STN. Method calls to `STNLogic` will be transformed into a C++ call to associated functions in STN. WeChat’s decision to implement STN in C++ is likely out of performance considerations. As an industry common practice, performance-critical code is implemented in C++ instead of Java. Note that the C++ code of STN is still running on the “:push” process.

![startTask Screenshot_20240222_185157](https://github.com/user-attachments/assets/27831cc3-0edc-4b7f-9231-2f5dcd9d9591)

Then, STNLogic calls into STN’s [`NetCore.StartTask()`](https://github.com/Tencent/mars/blob/fccccddeaa6fe2540af11c9e99ce3e12bd10dde6/mars/stn/src/net\_core.cc\#L306). Most of the functions that were actually called are built from the open source Mars, so we could simply read their source code. The main job of `NetCore` is to decide whether to use Longlink or Shortlink. Once decided, NetCore initializes the [`LongLinkTaskManager`](https://github.com/Tencent/mars/blob/fccccddeaa6fe2540af11c9e99ce3e12bd10dde6/mars/stn/src/longlink\_task\_manager.cc\#L59) and [`ShortLinkTaskManager`](https://github.com/Tencent/mars/blob/fccccddeaa6fe2540af11c9e99ce3e12bd10dde6/mars/stn/src/shortlink\_task\_manager.cc\#L61).

The Longlink and Shortlink Task Managers are responsible for establishing the underlying connections. In case of Longlink, the Task Manager establishes a TCP connection, and for Shortlink an HTTP connection. The Task Managers are also in charge of the lifecycle of a connection, when a lifecycle stage is reached, corresponding callback functions are called. Among them, the [`__RunOnStartTask()`](https://github.com/Tencent/mars/blob/fccccddeaa6fe2540af11c9e99ce3e12bd10dde6/mars/stn/src/shortlink\_task\_manager.cc\#L309) callback function is the most important for our topic. It is called when a task is started. It is responsible for starting the next two stages: Req2Buf and “MMTLS Encryption and Transport Protocols”. `__RunOnStartTask()` and other callback functions exist in both `ShortLinkTaskManager` and `LongLinkTaskManager`, though with different implementations.

### Business-layer serialization and encryption

As previously mentioned, `__RunOnStartTask()` callbacks of STN Task Managers are responsible for starting a task. One essential part of this process is to prepare the data to be sent. So far, the request data is still only stored in request objects, and has not been encrypted. The request data needs to be turned into a byte array (serialization), and then encrypted. `__RunOnStartTask()` achieves serialization and encryption by calling `MMNativeNetTaskAdapter.req2Buf()`. req2Buf() is a Java function that runs on the “:push” process.  req2Buf() will in turn call the `.toProtoBuf()` method defined by the particular request object, which would convert the in-memory request object into a byte array. Note that each request object can implement their own `.toProtoBuf()` method, so the serialization might be different across different request types.

After receiving the serialized byte array from `.toProtoBuf()`, `req2Buf()` will encrypt it. Depending on a series of conditional checks, `req2Buf()` will use different kinds of encryption by calling different encryption methods. This forms the Business-layer Encryption which we will discuss in detail in later sections. The most important conditional check is whether the client is already logged in. As we will describe later, the Business-layer Encryption uses AES-CBC when logged-in and AES-GCM when logged-out. When the client is logged-out, `req2Buf()` invokes a native function `HybridEcdhEncrypt()` located within libwechatmm.so to use AES-GCM encryption.  When the client is logged-in, `req2Buf()` invokes a native function `pack()` located within libMMProtocalJni.so to use AES-CBC.

### MMTLS encryption and transport protocols

Now, we turn our attention briefly back to `__RunOnStartTask()`. After `MMNativeNetTaskAdapter.req2Buf()` completes the Business-layer Encryption and serialization of data, `req2Buf()` returns to `__RunOnStartTask()`, which [initiates](https://github.com/Tencent/mars/blob/a7e9d52242acde849c1a1c4ada98b4579585c12c/mars/stn/src/shortlink\_task\_manager.cc\#L518) the module `ShortLinkWithMMTLS` (in case when using Shortlink) or `LongLinkWithMMTLS` (in case of Longlink), which is in charge of MMTLS Encryption and transport protocols. In the remainder of this section we focus on examining the Shortlink-related components, but not the Longlink ones. There are many more components involved in establishing a Longlink connection since the program has to manage the various connection states of TCP and also handle more than one cycle of sending and receiving data.

`ShortLinkWithMMTLS` is an extended version of the open-source [`ShortLink`](https://github.com/Tencent/mars/blob/8dd8b01e69f365f2302ff0dce12ae149d0145ca1/mars/stn/src/shortlink.cc\#L139) class. Their crucial difference is within their `__RunReadWrite()` functions. In `ShortLinkWithMMTLS.__RunReadWrite()`, functions performing the MMTLS Encryption (`ShortLinkWithMMTLS.__MakeTlsPayload()`) are called, whereas in [`ShortLink.__RunReadWrite()`](https://github.com/Tencent/mars/blob/8dd8b01e69f365f2302ff0dce12ae149d0145ca1/mars/stn/src/shortlink.cc\#L544), they are not. Actually, `__MakeTlsPayload()` only exists in WeChat and not in the open source Mars.

`ShortLinkWithMMTLS.__RunReadWrite()` also calls `ShortLinkWithMMTLS.__MakeHttpPayload()` to construct the HTTP request headers.

Finally, `__RunReadWrite()` calls the operating system API to establish TCP sockets and sends the encrypted and packaged data.

### Peculiarities of WeChat code

Throughout the code that we have been examining, we found their naming (of modules and symbols) and architecture often does not follow software engineering best practices. To illustrate, here are a few points that we found confusing through our reverse engineering:

* In `libMMProficalJni.so`, there is a function called `packHybridEcdh()`, which is called to encode the ciphertext returned by `HybridEcdhEncrypt()`. Unlike `pack()` in the same module which we previously mentioned, `packHybridEcdh()` does not perform encryption.  
* If the request type number equals 381 (which corresponds to a Scene Class named “NetSceneGetCert”), req2Buf() does not invoke AES-CBC or AES-GCM. Instead, the RR Class implements its own encryption and packing, which in turn still invokes `HybridEcdhEncrypt()` under certain circumstances.  
* In `libMMProtocalJni.so`, there are a few functions with similar names to `pack()`, including `packHybrid()` and `packDoubleHybrid()`. We do not observe them being invoked in our dynamic analysis, however, based on static analysis, they are still referenced in a lot of other modules. We suspect that they might have been used by earlier versions of Business-layer encryption.

### Further research utilizing Scene Classes

In the above sections, we have shown that WeChat uses a unified architecture to send network requests. This architectural understanding can help us (and future researchers) answer the following questions:

* For a server API, **what** user data is collected? To answer this, we can simply look at the fields defined in the API’s corresponding RR Class.  
* For a specific kind of user data, **when** is it collected? To answer this, we can simply: 1\) find all the RR classes that include the field that we’re interested in, 2\) find the corresponding Scene Classes of those RR Classes, 3\) examine what other components call into these Scene Classes.

Using this technique, we plan to further look into the inner workings of WeChat.
