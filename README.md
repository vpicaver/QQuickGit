# QQuickGit
Qt libgit2 interface

## Testcases
Make sure you have rsa keys generated and upload to github or the testcase will fail.

You can generate ssh rsa keys:
```
ssh-keygen -t rsa
```

Currently RSA keys are the only keys supported. Upload the public key to github.

```
-------------------------------------------------------------------------------
GitFutureWatcher should watch git repository futures correctly
-------------------------------------------------------------------------------
/Users/cave/Documents/projects/QQuickGit/tests/test_GitFutureWatcher.cpp:18
...............................................................................

/Users/cave/Documents/projects/QQuickGit/SignalSpyChecker/SignalSpyChecker.cpp:86: FAILED:
  CHECK( okay )
with expansion:
  false
with messages:
  Dir:/Users/cave/Documents/projects/QQuickGit/build/Qt_6_8_3_for_macOS-Debug/
  clone-test
  Key:errorMessageChangedSpy
  SignalSpy:1 expected:0

Spy checker will fail. Place breakpoint here to debug. checkSpies()
/Users/cave/Documents/projects/QQuickGit/SignalSpyChecker/SignalSpyChecker.cpp:86: FAILED:
  CHECK( okay )
with expansion:
  false
with messages:
  Dir:/Users/cave/Documents/projects/QQuickGit/build/Qt_6_8_3_for_macOS-Debug/
  clone-test
  Key:hasErrorChangedSpy
  SignalSpy:1 expected:0

/Users/cave/Documents/projects/QQuickGit/tests/test_GitFutureWatcher.cpp:54: FAILED:
  CHECK( watcher.errorMessage().isEmpty() )
with expansion:
  false
with messages:
  Dir:/Users/cave/Documents/projects/QQuickGit/build/Qt_6_8_3_for_macOS-Debug/
  clone-test
  Error message:remote rejected authentication: Failed getting response

===============================================================================
```
