//Catch includes
#include <catch2/catch_test_macros.hpp>

//libgit2
#include "git2.h"

//Our inculdes
#include "GitRepository.h"
#include "Account.h"
#include "TestUtilities.h"
#include "ProgressState.h"
#include "LfsStore.h"

//Qt includes
#include <QDir>
#include <QDebug>
#include <QSignalSpy>
#include <QFuture>
#include <QTemporaryDir>
#include <QFile>
#include <QUuid>
#include <QTcpServer>
#include <QTcpSocket>

//Std includes
#include <iostream>

//Async include
#include "asyncfuture.h"

//Monad
#include "Monad/Result.h"
using namespace Monad;

const int defaultTimeout = 10000;

using namespace QQuickGit;

auto waitForClone(QFuture<ResultBase> future, int timeout = defaultTimeout) {
    REQUIRE(AsyncFuture::waitForFinished(future, timeout));
    INFO("Clone error:" << future.result().errorMessage().toStdString() << "code:" << future.result().errorCode());
    CHECK(!future.result().hasError());
}

auto waitForGitFuture(QFuture<ResultBase> future, int timeout = defaultTimeout) {
    REQUIRE(AsyncFuture::waitForFinished(future, timeout));
    INFO("Git error:" << future.result().errorMessage().toStdString() << "code:" << future.result().errorCode());
    CHECK(!future.result().hasError());
}

class ScopedRemoteBranchCleanup {
public:
    ScopedRemoteBranchCleanup(GitRepository* repository, QString branchName, int timeoutMs)
        : mRepository(repository),
          mBranchName(std::move(branchName)),
          mTimeoutMs(timeoutMs)
    {
    }

    void release()
    {
        mActive = false;
    }

    ~ScopedRemoteBranchCleanup()
    {
        if (!mActive || !mRepository || mBranchName.isEmpty()) {
            return;
        }

        if (!mRepository->remoteBranchExists(QStringLiteral("origin/%1").arg(mBranchName))) {
            return;
        }

        auto cleanupFuture = mRepository->deleteBranchRemote(mBranchName);
        AsyncFuture::waitForFinished(cleanupFuture, mTimeoutMs);
        if (cleanupFuture.result().hasError()) {
            qDebug() << "Cleanup delete remote branch failed for"
                     << mBranchName
                     << cleanupFuture.result().errorMessage();
        }
    }

private:
    GitRepository* mRepository = nullptr;
    QString mBranchName;
    int mTimeoutMs = 0;
    bool mActive = true;
};

TEST_CASE("GitRepository should work correctly", "[GitRepository]") {
    QDir cloneDir("clone-test");

    INFO("Dir:" << QDir::toNativeSeparators(cloneDir.absolutePath()).toStdString());
    CHECK(cloneDir.removeRecursively());

    GitRepository repository;
    repository.setDirectory(cloneDir);
    waitForClone(repository.clone(QUrl("ssh://git@github.com/vpicaver/libgit2-test.git")));

    git_repository* repo;
    REQUIRE(git_repository_open(&repo, cloneDir.absolutePath().toLocal8Bit().constData()) == GIT_OK);

    git_oid firstId;
    git_oid_fromstr(&firstId, "220b815025d29d454c975feb61d13f2d5cf26e66");

    git_object* firstCommit;
    REQUIRE(git_object_lookup(&firstCommit, repo, &firstId, GIT_OBJECT_COMMIT) == GIT_OK);

    //Reset the repo to the first commit
    git_checkout_options checkoutOptions = GIT_CHECKOUT_OPTIONS_INIT;
    REQUIRE(git_reset(repo, firstCommit, GIT_RESET_HARD, &checkoutOptions) == GIT_OK);

    //Force push back to initial commit
    auto pushFuture = repository.push("+refs/heads/main:refs/heads/main");
    AsyncFuture::waitForFinished(pushFuture, defaultTimeout);
    INFO("Force push error:" << pushFuture.result().errorMessage().toStdString());
    REQUIRE(!pushFuture.result().hasError());

    git_object_free(firstCommit);

    CHECK(cloneDir.exists("README.md"));

    QDir cloneDir2("clone-test2");
    CHECK(cloneDir2.removeRecursively());

    GitRepository repository2;
    repository2.setDirectory(cloneDir2);
    waitForClone(repository2.clone(repository.remoteUrl()));

    SECTION("hasCommits should reflect repository history") {
        CHECK(repository.hasCommits());
        CHECK(repository2.hasCommits());

        QTemporaryDir tempDir;
        REQUIRE(tempDir.isValid());

        GitRepository emptyRepository;
        emptyRepository.setDirectory(QDir(tempDir.path()));
        emptyRepository.initRepository();

        CHECK(emptyRepository.hasCommits() == false);

        {
            QFile file(tempDir.filePath("initial.txt"));
            REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate | QFile::Text));
            file.write("initial commit\n");
        }

        emptyRepository.checkStatus();

        Account account;
        account.setName("Tester");
        account.setEmail("tester@example.com");
        emptyRepository.setAccount(&account);

        REQUIRE_NOTHROW(emptyRepository.commitAll("Initial", "Created repo"));

        CHECK(emptyRepository.hasCommits());
    }

    SECTION("Test add remote") {
        auto remotes = repository.remotes();
        REQUIRE(remotes.size() == 1);
        CHECK(remotes.at(0).name().toStdString() == "origin");
        CHECK(remotes.at(0).url().toString().toStdString() == "ssh://git@github.com/vpicaver/libgit2-test.git");

        repository.addRemote("github", QUrl("ssh://git@github.com/vpicaver/libgit2-test2.git"));
        remotes = repository.remotes();
        REQUIRE(remotes.size() == 2);

        GitRemoteInfo originInfo("origin", QUrl("ssh://git@github.com/vpicaver/libgit2-test.git"));
        CHECK(std::find(remotes.begin(), remotes.end(), originInfo) != remotes.end());

        GitRemoteInfo githubInfo("github", QUrl("ssh://git@github.com/vpicaver/libgit2-test2.git"));
        CHECK(std::find(remotes.begin(), remotes.end(), githubInfo) != remotes.end());
    }

    SECTION("Open repository should work") {
        GitRepository rep2;
        rep2.setDirectory(cloneDir);
        CHECK_NOTHROW(rep2.initRepository());
    }

    SECTION("Status should work correctly when files are added") {
        QSignalSpy modifiedCountChangedSpy(&repository, &GitRepository::modifiedFileCountChanged);

        repository.checkStatus();
        CHECK(repository.modifiedFileCount() == 0);
        CHECK(modifiedCountChangedSpy.size() == 0);

        {
            QFile file(cloneDir.absoluteFilePath("test.txt"));
            REQUIRE(file.open(QFile::WriteOnly));
            file.write("Hello world!\n");
        }

        repository.checkStatus();
        CHECK(repository.modifiedFileCount() == 1);
        CHECK(modifiedCountChangedSpy.size() == 1);

        {
            QFile file(cloneDir.absoluteFilePath("test2.txt"));
            REQUIRE(file.open(QFile::WriteOnly));
            file.write("Hello world! 2\n");
        }

        repository.checkStatus();
        CHECK(repository.modifiedFileCount() == 2);
        CHECK(modifiedCountChangedSpy.size() == 2);

        SECTION("Status should ignore files in .gitignore") {
            // Add *.ignore pattern to .gitignore
            {
                QFile file(cloneDir.absoluteFilePath(".gitignore"));
                REQUIRE(file.open(QFile::WriteOnly));
                file.write("*.ignore\n");
            }

            // Create an .ignore file
            for(int i = 0; i < 10; i++) {
                QFile file(cloneDir.absoluteFilePath(QString("test%1.ignore").arg(i)));
                REQUIRE(file.open(QFile::WriteOnly));
                file.write("This should be ignored!\n");
            }

            repository.checkStatus();
            // The status count should be 3 because 10 files that are ignore should be ignored, but we're
            // also adding the .gitignore file
            CHECK(repository.modifiedFileCount() == 3);
            CHECK(modifiedCountChangedSpy.size() == 3);
        }

        SECTION("Commit all changes") {
            Account account;
            account.setName("Test name");
            account.setEmail("test@email.com");

            repository.setAccount(&account);
            repository2.setAccount(&account);

            CHECK_NOTHROW(repository.commitAll("Test Subject", "I'm a description"));

            auto checkHEAD = [repo, &account](const QString& message, QStringList paths) {
                git_reference* ref;
                REQUIRE(git_repository_head(&ref, repo) == GIT_OK);

                auto id = git_reference_target(ref);
                REQUIRE(id != nullptr);

                git_commit* commit;
                REQUIRE(git_commit_lookup(&commit, repo, id) == GIT_OK);
                auto signature = git_commit_committer(commit);

                CHECK(QString::fromLocal8Bit(signature->name).toStdString() == account.name().toStdString());
                CHECK(QString::fromLocal8Bit(signature->email).toStdString() == account.email().toStdString());

                auto commitMessage = git_commit_message(commit);
                CHECK(message.toStdString() == commitMessage);

                git_tree* tree;
                REQUIRE(git_commit_tree(&tree, commit) == GIT_OK);

                auto hasFile = [](git_tree* tree, const QString& filePath) {
                    git_tree_entry* entry;
                    CHECK(git_tree_entry_bypath(&entry, tree, filePath.toLocal8Bit().constData()) == GIT_OK);
                    git_tree_entry_free(entry);
                };

                for(auto path : paths) {
                    hasFile(tree, path);
                }

                git_commit_free(commit);
                git_tree_free(tree);
                git_reference_free(ref);
            };

            checkHEAD("Test Subject\n\nI'm a description",
                      {
                          "test.txt",
                          "test2.txt"
                      });

            //            std::cout << "Dir:" << QDir::toNativeSeparators(cloneDir.absolutePath()).toStdString() << std::endl;

            SECTION("Add another commit") {

                {
                    QFile file(cloneDir.absoluteFilePath("test2.txt"));
                    REQUIRE(file.open(QFile::Append));
                    file.write("sauce\n");
                }

                CHECK_NOTHROW(repository.commitAll("Test2", "sauce written"));

                checkHEAD("Test2\n\nsauce written",
                          {
                              "test2.txt"
                          });


                SECTION("Add another file in a subdirectory") {

                    cloneDir.mkdir("test");
                    {
                        QFile file(cloneDir.absoluteFilePath("test/test3.txt"));
                        REQUIRE(file.open(QFile::WriteOnly));
                        file.write("sauce2\n");
                    }

                    account.setName("dude");
                    account.setEmail("dude@email.com");

                    CHECK_NOTHROW(repository.commitAll("Test3", "sauce2"));

                    checkHEAD("Test3\n\nsauce2",
                              {
                                  "test/test3.txt"
                              });
                }
            }

            SECTION("Push HEAD") {
                auto pushFuture = repository.push();
                AsyncFuture::waitForFinished(pushFuture, defaultTimeout);
                INFO("Force push error:" << pushFuture.result().errorMessage().toStdString());
                REQUIRE(!pushFuture.result().hasError());

                //Check that the remote refspec is at the current head
                git_reference* headRef;
                REQUIRE(git_repository_head(&headRef, repo) == GIT_OK);

                git_reference* remoteHeadRef;
                REQUIRE(git_reference_lookup(&remoteHeadRef, repo, "refs/remotes/origin/main") == GIT_OK);

                auto headId = git_reference_target(headRef);
                auto remoteId = git_reference_target(remoteHeadRef);
                CHECK(git_oid_cmp(headId, remoteId) == 0);

                SECTION("Fetch test") {
                    auto fetchFuture = repository2.fetch();

                    int progressCount = 0;
                    AsyncFuture::observe(fetchFuture).onProgress([&progressCount, fetchFuture]() {
                        progressCount++;
                    });

                    AsyncFuture::waitForFinished(fetchFuture, defaultTimeout);
                    CHECK(fetchFuture.result().errorMessage().toStdString() == "");
                    CHECK(!fetchFuture.progressText().isEmpty());
                    CHECK(progressCount > 0);

                    git_repository* repo2;
                    REQUIRE(git_repository_open(&repo2, repository2.directory().absolutePath().toLocal8Bit().constData()) == GIT_OK);

                    //Check tha fetch is working correctly
                    git_reference* headRef2;
                    REQUIRE(git_repository_head(&headRef2, repo2) == GIT_OK);

                    auto head2Id = git_reference_target(headRef2);
                    CHECK(git_oid_cmp(head2Id, &firstId) == 0);

                    git_reference* remoteHead2Ref;
                    REQUIRE(git_reference_lookup(&remoteHead2Ref, repo2, "refs/remotes/origin/main") == GIT_OK);
                    auto remote2Id = git_reference_target(remoteHead2Ref);
                    CHECK(git_oid_cmp(remoteId, remote2Id) == 0);

                    git_reference_free(remoteHead2Ref);
                    git_reference_free(headRef2);
                    git_repository_free(repo2);
                }

                SECTION("Merge Already up-to-date") {
                    GitRepository::MergeResult result;
                    CHECK_NOTHROW(result = repository.merge({"refs/remotes/origin/main"}));
                    CHECK(result.state() == GitRepository::MergeResult::AlreadyUpToDate);
                }

                SECTION("Pull fast forward") {
                    auto pullFuture = repository2.pull();

                    int progressCount = 0;
                    AsyncFuture::observe(pullFuture).onProgress([&progressCount, pullFuture]() {
                        progressCount++;
                    });

                    AsyncFuture::waitForFinished(pullFuture);
                    CHECK(pullFuture.result().errorMessage().toStdString() == "");
                    CHECK(pullFuture.result().value().state() == GitRepository::MergeResult::FastForward);
                    CHECK(progressCount > 0);
                    CHECK(!pullFuture.progressText().isEmpty());

                    //Repositories should be at the same place
                    git_repository* repo2;
                    REQUIRE(git_repository_open(&repo2, repository2.directory().absolutePath().toLocal8Bit().constData()) == GIT_OK);

                    git_reference* headRef2;
                    REQUIRE(git_repository_head(&headRef2, repo2) == GIT_OK);

                    auto head2Id = git_reference_target(headRef2);

                    git_reference* remoteHead2Ref;
                    REQUIRE(git_reference_lookup(&remoteHead2Ref, repo2, "refs/remotes/origin/main") == GIT_OK);
                    auto remote2Id = git_reference_target(remoteHead2Ref);
                    CHECK(git_oid_cmp(head2Id, remote2Id) == 0);
                    CHECK(git_oid_cmp(remoteId, remote2Id) == 0);

                    git_reference_free(remoteHead2Ref);
                    git_reference_free(headRef2);
                    git_repository_free(repo2);
                }

                SECTION("Pull merge no conflicts") {
                    //Make another commit on repo
                    cloneDir.mkdir("test");
                    {
                        QFile file(cloneDir.absoluteFilePath("test/test4.txt"));
                        REQUIRE(file.open(QFile::WriteOnly));
                        file.write("sauce3\n");
                    }

                    CHECK_NOTHROW(repository.commitAll("repository", ""));
                    auto pushFuture = repository.push();
                    AsyncFuture::waitForFinished(pushFuture, defaultTimeout);
                    INFO("Force push error:" << pushFuture.result().errorMessage().toStdString());
                    REQUIRE(!pushFuture.result().hasError());

                    //Make another commit on repo2
                    cloneDir2.mkdir("test");
                    {
                        QFile file(cloneDir2.absoluteFilePath("test/test3.txt"));
                        REQUIRE(file.open(QFile::WriteOnly));
                        file.write("sauce2\n");
                    }

                    CHECK_NOTHROW(repository2.commitAll("repository2", ""));
                    auto pullFuture2 = repository2.pull();
                    AsyncFuture::waitForFinished(pullFuture2, defaultTimeout);
                    CHECK(pullFuture2.result().errorMessage().toStdString() == "");
                    CHECK(pullFuture2.result().value().state() == GitRepository::MergeResult::MergeCommitCreated);

                    auto pushFuture2 = repository2.push();
                    AsyncFuture::waitForFinished(pushFuture2, defaultTimeout);
                    INFO("Force push error:" << pushFuture2.result().errorMessage().toStdString());
                    REQUIRE(!pushFuture2.result().hasError());

                    auto pullFuture = repository.pull();
                    AsyncFuture::waitForFinished(pullFuture, defaultTimeout);
                    CHECK(pullFuture.result().errorMessage().toStdString() == "");
                    CHECK(pullFuture.result().value().state() == GitRepository::MergeResult::FastForward);

                    git_repository* repo2;
                    REQUIRE(git_repository_open(&repo2, repository2.directory().absolutePath().toLocal8Bit().constData()) == GIT_OK);

                    git_reference* headRef2;
                    REQUIRE(git_repository_head(&headRef2, repo2) == GIT_OK);

                    auto head2Id = git_reference_target(headRef2);

                    git_reference* remoteHead2Ref;
                    REQUIRE(git_reference_lookup(&remoteHead2Ref, repo2, "refs/remotes/origin/main") == GIT_OK);
                    auto remote2Id = git_reference_target(remoteHead2Ref);
                    CHECK(git_oid_cmp(head2Id, remote2Id) == 0);

                    REQUIRE(git_reference_lookup(&remoteHeadRef, repo, "refs/remotes/origin/main") == GIT_OK);
                    auto remoteId = git_reference_target(remoteHeadRef);

                    CHECK(git_oid_cmp(remoteId, remote2Id) == 0);

                    git_annotated_commit* headCommit;
                    git_commit* commit;
                    git_annotated_commit_from_ref(&headCommit, repo2, headRef2);
                    git_commit_lookup(&commit, repo2, git_annotated_commit_id(headCommit));
                    auto message = git_commit_message(commit);
                    CHECK(QString::fromLocal8Bit(message).toStdString() == "Merged branch origin/main");

                    git_annotated_commit_free(headCommit);
                    git_commit_free(commit);
                    git_reference_free(remoteHead2Ref);
                    git_reference_free(headRef2);
                    git_repository_free(repo2);

                }

                git_reference_free(headRef);
                git_reference_free(remoteHeadRef);
            }


            SECTION("pullPush should work correctly") {
                //Make another commit on repo2
                cloneDir2.mkdir("test");
                {
                    QFile file(cloneDir2.absoluteFilePath("test/test3.txt"));
                    REQUIRE(file.open(QFile::WriteOnly));
                    file.write("sauce2\n");
                }

                CHECK_NOTHROW(repository2.commitAll("repository2", ""));

                auto pushFuture2 = repository2.push();
                AsyncFuture::waitForFinished(pushFuture2, defaultTimeout);
                INFO("Force push error:" << pushFuture2.result().errorMessage().toStdString());
                REQUIRE(!pushFuture2.result().hasError());

                SECTION("with pull and push") {
                    //Make another commit on repo
                    cloneDir.mkdir("test");
                    {
                        QFile file(cloneDir.absoluteFilePath("test/test4.txt"));
                        REQUIRE(file.open(QFile::WriteOnly));
                        file.write("sauce3\n");
                    }

                    CHECK_NOTHROW(repository.commitAll("repository", ""));
                    auto pullPushFuture = repository.pullPush();

                    int progressCount = 0;
                    AsyncFuture::observe(pullPushFuture).onProgress([&progressCount, pullPushFuture]() {
                        progressCount++;
                    });

                    AsyncFuture::waitForFinished(pullPushFuture, defaultTimeout);
                    INFO("Force push error:" << pullPushFuture.result().errorMessage().toStdString());
                    REQUIRE(!pullPushFuture.result().hasError());
                    CHECK(!pullPushFuture.progressText().isEmpty());
                    CHECK(progressCount > 0);

                    auto pullFuture2 = repository2.pull();
                    AsyncFuture::waitForFinished(pullFuture2, defaultTimeout);

                    git_repository* repo2;
                    REQUIRE(git_repository_open(&repo2, repository2.directory().absolutePath().toLocal8Bit().constData()) == GIT_OK);

                    git_reference* headRef2;
                    REQUIRE(git_repository_head(&headRef2, repo2) == GIT_OK);

                    auto head2Id = git_reference_target(headRef2);

                    git_reference* remoteHead2Ref;
                    REQUIRE(git_reference_lookup(&remoteHead2Ref, repo2, "refs/remotes/origin/main") == GIT_OK);
                    auto remote2Id = git_reference_target(remoteHead2Ref);
                    CHECK(git_oid_cmp(head2Id, remote2Id) == 0);

                    git_reference* remoteHeadRef;
                    REQUIRE(git_reference_lookup(&remoteHeadRef, repo, "refs/remotes/origin/main") == GIT_OK);
                    auto remoteId = git_reference_target(remoteHeadRef);

                    CHECK(git_oid_cmp(remoteId, remote2Id) == 0);
                }

                SECTION("with Merge conflict") {
                    //Make another commit on repo
                    cloneDir.mkdir("test");
                    {
                        QFile file(cloneDir.absoluteFilePath("test/test3.txt"));
                        REQUIRE(file.open(QFile::WriteOnly));
                        file.write("sauce3\n");
                    }

                    CHECK_NOTHROW(repository.commitAll("repository", ""));
                    auto pullPushFuture = repository.pullPush();
                    AsyncFuture::waitForFinished(pullPushFuture, defaultTimeout);
                    INFO("Force push error:" << pullPushFuture.result().errorMessage().toStdString());
                    CHECK(!pullPushFuture.result().hasError());
                    CHECK(pullPushFuture.result().errorMessage().toStdString() == "");
                }
            }
        }
    }

    SECTION("Create branch. commit. push. delete remote branch") {
        const QString branchName = QStringLiteral("testBranch-%1")
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces).left(8));
        ScopedRemoteBranchCleanup cleanupGuard(&repository, branchName, defaultTimeout);
        CHECK_NOTHROW(repository.createBranch(branchName));

        Account account;
        account.setName("Test name");
        account.setEmail("test@email.com");

        repository.setAccount(&account);

        {
            QFile file(cloneDir.absoluteFilePath("test8.txt"));
            REQUIRE(file.open(QFile::WriteOnly));
            file.write("Hello world :D :D!\n");
        }

        CHECK_NOTHROW(repository.commitAll(branchName, ""));

        auto pushFuture = repository.push();
        AsyncFuture::waitForFinished(pushFuture, defaultTimeout);
        INFO("Force push error:" << pushFuture.result().errorMessage().toStdString());
        REQUIRE(!pushFuture.result().hasError());

        auto deleteFuture = repository.deleteBranchRemote(repository.headBranchName());
        AsyncFuture::waitForFinished(deleteFuture, defaultTimeout);
        INFO("Delete Future Error:" << deleteFuture.result().errorMessage().toStdString());
        REQUIRE(!deleteFuture.result().hasError());
        cleanupGuard.release();

        CHECK(!repository.remoteBranchExists(QStringLiteral("origin/%1").arg(branchName)));
    }

    git_repository_free(repo);
}

TEST_CASE("Merge should work correctly", "[GitRepository]") {
    auto tempDir = TestUtilities::createUniqueTempDir();
    GitRepository repo;
    repo.setDirectory(tempDir);
    CHECK_NOTHROW(repo.initRepository());

    Account account;
    account.setName("Sauce");
    account.setEmail("sauce@email.com");

    repo.setAccount(&account);

    {
        QFile file(tempDir.absoluteFilePath("test.txt"));
        REQUIRE(file.open(QFile::WriteOnly));
        file.write("Hello world!\n");
    }

    CHECK_NOTHROW(repo.commitAll("test", "first test commit"));

    CHECK(repo.headBranchName().toStdString() == "master");

    CHECK_NOTHROW(repo.createBranch("testBranch"));
    CHECK(repo.headBranchName().toStdString() == "testBranch");

    SECTION("Merge already up-to-date") {
        GitRepository::MergeResult result;
        CHECK_NOTHROW(result = repo.merge({"master"}));
        CHECK(result.state() == GitRepository::MergeResult::AlreadyUpToDate);
    }

    SECTION("Merge") {
        {
            QFile file(tempDir.absoluteFilePath("test2.txt"));
            REQUIRE(file.open(QFile::WriteOnly));
            file.write("Hello world 2!\n");
        }

        CHECK_NOTHROW(repo.commitAll("test1", "2 test commit"));

        SECTION("Fast forward") {
            waitForGitFuture(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            GitRepository::MergeResult result;
            CHECK_NOTHROW(result = repo.merge({"testBranch"}));

            CHECK(result.state() == GitRepository::MergeResult::FastForward);
        }

        SECTION("Simple merge, no conflicts") {
            waitForGitFuture(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            {
                QFile file(tempDir.absoluteFilePath("test3.txt"));
                REQUIRE(file.open(QFile::WriteOnly));
                file.write("Hello world 3!\n");
            }

            repo.commitAll("test2", "3 test commit");

            GitRepository::MergeResult result;
            CHECK_NOTHROW(result = repo.merge({"testBranch"}));

            CHECK(result.state() == GitRepository::MergeResult::MergeCommitCreated);
        }

        SECTION("Test merge conflicts") {
            {
                QFile file(tempDir.absoluteFilePath("test.txt"));
                REQUIRE(file.open(QFile::WriteOnly));
                file.write(":D Hello world!\n");
            }

            repo.commitAll("test2", "3 test commit");

            waitForGitFuture(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            {
                QFile file(tempDir.absoluteFilePath("test.txt"));
                REQUIRE(file.open(QFile::WriteOnly));
                file.write(":( Hello world!\n");
            }

            repo.commitAll("test3", "4 test commit");

            GitRepository::MergeResult result;
            CHECK_NOTHROW(result = repo.merge({"testBranch"}));

            CHECK(result.state() == GitRepository::MergeResult::MergeCommitCreated);
            QFile file(tempDir.absoluteFilePath("test.txt"));
            REQUIRE(file.open(QFile::ReadOnly));
            auto fileContent = file.readAll();
            CHECK(fileContent.toStdString() == ":( Hello world!\n");
        }

        SECTION("Test merge conflict when ours renames and theirs modifies") {
            waitForGitFuture(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            CHECK_NOTHROW(repo.createBranch("renameBranch"));
            CHECK(repo.headBranchName().toStdString() == "renameBranch");

            REQUIRE(QFile::rename(tempDir.absoluteFilePath("test.txt"),
                                  tempDir.absoluteFilePath("renamed.txt")));
            CHECK_NOTHROW(repo.commitAll("rename", "rename test.txt"));

            waitForGitFuture(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            {
                QFile file(tempDir.absoluteFilePath("test.txt"));
                REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate));
                file.write("remote-style change\n");
            }

            CHECK_NOTHROW(repo.commitAll("modify", "modify test.txt"));

            waitForGitFuture(repo.checkout("refs/heads/renameBranch"));
            CHECK(repo.headBranchName().toStdString() == "renameBranch");

            GitRepository::MergeResult result;
            CHECK_NOTHROW(result = repo.merge({"master"}));

            CHECK(result.state() == GitRepository::MergeResult::MergeCommitCreated);
            CHECK(QFile::exists(tempDir.absoluteFilePath("renamed.txt")));
            CHECK(!QFile::exists(tempDir.absoluteFilePath("test.txt")));

            QFile file(tempDir.absoluteFilePath("renamed.txt"));
            REQUIRE(file.open(QFile::ReadOnly));
            CHECK(file.readAll().toStdString() == "remote-style change\n");
        }

        SECTION("Test merge conflict when ours modifies and theirs renames") {
            waitForGitFuture(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            CHECK_NOTHROW(repo.createBranch("renameBranch2"));
            CHECK(repo.headBranchName().toStdString() == "renameBranch2");

            REQUIRE(QFile::rename(tempDir.absoluteFilePath("test.txt"),
                                  tempDir.absoluteFilePath("renamed2.txt")));
            CHECK_NOTHROW(repo.commitAll("rename", "rename test.txt to renamed2.txt"));

            waitForGitFuture(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            {
                QFile file(tempDir.absoluteFilePath("test.txt"));
                REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate));
                file.write("ours modification\n");
            }

            CHECK_NOTHROW(repo.commitAll("modify", "modify test.txt"));

            GitRepository::MergeResult result;
            CHECK_NOTHROW(result = repo.merge({"renameBranch2"}));

            CHECK(result.state() == GitRepository::MergeResult::MergeCommitCreated);
            CHECK(QFile::exists(tempDir.absoluteFilePath("renamed2.txt")));
            CHECK(!QFile::exists(tempDir.absoluteFilePath("test.txt")));

            QFile file(tempDir.absoluteFilePath("renamed2.txt"));
            REQUIRE(file.open(QFile::ReadOnly));
            CHECK(file.readAll().toStdString() == "ours modification\n");
        }

        SECTION("Test merge conflict when ours renames a directory-like subtree and theirs modifies one file") {
            waitForGitFuture(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            REQUIRE(tempDir.mkpath(QStringLiteral("Trip/notes")));
            {
                QFile tripFile(tempDir.absoluteFilePath("Trip/Trip.cwtrip"));
                REQUIRE(tripFile.open(QFile::WriteOnly | QFile::Truncate));
                tripFile.write("date=2024-01-01\n");
            }
            {
                QFile noteFile(tempDir.absoluteFilePath("Trip/notes/1.cwnote"));
                REQUIRE(noteFile.open(QFile::WriteOnly | QFile::Truncate));
                noteFile.write("note\n");
            }
            CHECK_NOTHROW(repo.commitAll("seed trip", "seed trip subtree"));

            CHECK_NOTHROW(repo.createBranch("renameTripBranch"));
            CHECK(repo.headBranchName().toStdString() == "renameTripBranch");

            REQUIRE(QDir(tempDir.absolutePath()).rename(QStringLiteral("Trip"),
                                                        QStringLiteral("Trip Renamed")));
            REQUIRE(QFile::rename(tempDir.absoluteFilePath("Trip Renamed/Trip.cwtrip"),
                                  tempDir.absoluteFilePath("Trip Renamed/Trip Renamed.cwtrip")));
            {
                QFile renamedTripFile(tempDir.absoluteFilePath("Trip Renamed/Trip Renamed.cwtrip"));
                REQUIRE(renamedTripFile.open(QFile::WriteOnly | QFile::Truncate));
                renamedTripFile.write("date=2024-01-01\nname=Trip Renamed\n");
            }
            CHECK_NOTHROW(repo.commitAll("rename trip", "rename trip subtree"));

            waitForGitFuture(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            {
                QFile tripFile(tempDir.absoluteFilePath("Trip/Trip.cwtrip"));
                REQUIRE(tripFile.open(QFile::WriteOnly | QFile::Truncate));
                tripFile.write("date=2024-08-23\n");
            }
            CHECK_NOTHROW(repo.commitAll("modify trip", "modify trip metadata"));

            GitRepository::MergeResult result;
            CHECK_NOTHROW(result = repo.merge({"renameTripBranch"}));

            CHECK(result.state() == GitRepository::MergeResult::MergeCommitCreated);
            CHECK(QFile::exists(tempDir.absoluteFilePath("Trip Renamed/Trip Renamed.cwtrip")));
            CHECK(QFile::exists(tempDir.absoluteFilePath("Trip Renamed/notes/1.cwnote")));
            CHECK_FALSE(QFile::exists(tempDir.absoluteFilePath("Trip/Trip.cwtrip")));
            CHECK_FALSE(QFile::exists(tempDir.absoluteFilePath("Trip/notes/1.cwnote")));

            QFile mergedTripFile(tempDir.absoluteFilePath("Trip Renamed/Trip Renamed.cwtrip"));
            REQUIRE(mergedTripFile.open(QFile::ReadOnly));
            const auto mergedTripContent = mergedTripFile.readAll();
            CHECK_FALSE(mergedTripContent.contains("<<<<<<<"));
            CHECK_FALSE(mergedTripContent.contains("======="));
            CHECK_FALSE(mergedTripContent.contains(">>>>>>>"));
            CHECK(mergedTripContent.contains("name=Trip Renamed"));
        }

        SECTION("Test no conflict markers when ours renames directory and both sides modify a file inside it") {
            // Regression: when one branch renames a directory AND both branches modify
            // a file inside it, reconcileRenameMap() calls mergeBuffers() which calls
            // git_merge_file(). When both sides changed the same line, this generates
            // conflict markers with path labels (e.g. "<<<<<<< Cave 3006/notes/1.cwnote")
            // rather than "<<<<<<< HEAD". These markers were staged and committed as-is.
            // The file must be long enough for libgit2's rename detection (similarity > 50%).
            waitForGitFuture(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            // Build a realistic-length JSON note file (~30 lines) so libgit2's rename
            // detection sees high similarity despite the one-field change.
            const QByteArray notePrefix =
                "{\n"
                " \"image\": {\n"
                "  \"size\": { \"width\": 3195, \"height\": 2564 },\n"
                "  \"dotPerMeter\": 3780,\n"
                "  \"path\": \"1.jpeg\"\n"
                " },\n"
                " \"rotation\": 0,\n"
                " \"scraps\": [\n"
                "  {\n"
                "   \"outlinePoints\": [\n"
                "    { \"x\": 0.555, \"y\": 0.496 },\n"
                "    { \"x\": 0.567, \"y\": 0.523 },\n"
                "    { \"x\": 0.589, \"y\": 0.538 },\n"
                "    { \"x\": 0.597, \"y\": 0.569 },\n"
                "    { \"x\": 0.610, \"y\": 0.583 },\n"
                "    { \"x\": 0.635, \"y\": 0.626 },\n"
                "    { \"x\": 0.647, \"y\": 0.662 },\n"
                "    { \"x\": 0.646, \"y\": 0.694 },\n"
                "    { \"x\": 0.648, \"y\": 0.731 },\n"
                "    { \"x\": 0.653, \"y\": 0.738 }\n"
                "   ],\n"
                "   \"type\": \"Plan\",\n"
                "   \"id\": \"0ff83d05-648f-4ab2-9336-e98b853f0871\"\n"
                "  }\n"
                " ],\n"
                " \"imageResolution\": {\n"
                "  \"value\": 96.012,\n"
                "  \"unit\": \"DotsPerInch\"\n"
                " },\n"
                " \"name\": \"1\",\n"
                " \"fileVersion\": {\n"
                "  \"version\": 8,\n";
            const QByteArray noteSuffix =
                " },\n"
                " \"id\": \"228fa0cc-2db5-45ed-b7ca-1d17ac93c207\"\n"
                "}\n";

            REQUIRE(tempDir.mkpath(QStringLiteral("Cave 3000/notes")));
            {
                QFile noteFile(tempDir.absoluteFilePath("Cave 3000/notes/1.cwnote"));
                REQUIRE(noteFile.open(QFile::WriteOnly | QFile::Truncate));
                noteFile.write(notePrefix);
                noteFile.write("  \"cavewhereVersion\": \"base\"\n");
                noteFile.write(noteSuffix);
            }
            CHECK_NOTHROW(repo.commitAll("seed note", "seed note file in Cave 3000"));

            // Ours branch: rename Cave 3000 -> Cave 3006 AND change the version field
            CHECK_NOTHROW(repo.createBranch("renameAndModifyBranch"));
            CHECK(repo.headBranchName().toStdString() == "renameAndModifyBranch");

            REQUIRE(QDir(tempDir.absolutePath()).rename(QStringLiteral("Cave 3000"),
                                                        QStringLiteral("Cave 3006")));
            {
                QFile noteFile(tempDir.absoluteFilePath("Cave 3006/notes/1.cwnote"));
                REQUIRE(noteFile.open(QFile::WriteOnly | QFile::Truncate));
                noteFile.write(notePrefix);
                noteFile.write("  \"cavewhereVersion\": \"ours-version\"\n");
                noteFile.write(noteSuffix);
            }
            CHECK_NOTHROW(repo.commitAll("rename and modify", "rename Cave dir and update version"));

            // Theirs (master): modify same field, no rename
            waitForGitFuture(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            {
                QFile noteFile(tempDir.absoluteFilePath("Cave 3000/notes/1.cwnote"));
                REQUIRE(noteFile.open(QFile::WriteOnly | QFile::Truncate));
                noteFile.write(notePrefix);
                noteFile.write("  \"cavewhereVersion\": \"theirs-version\"\n");
                noteFile.write(noteSuffix);
            }
            CHECK_NOTHROW(repo.commitAll("theirs modify", "update version on master"));

            // Back to ours, merge theirs
            waitForGitFuture(repo.checkout("refs/heads/renameAndModifyBranch"));
            CHECK(repo.headBranchName().toStdString() == "renameAndModifyBranch");

            GitRepository::MergeResult result;
            CHECK_NOTHROW(result = repo.merge({"master"}));
            CHECK(result.state() == GitRepository::MergeResult::MergeCommitCreated);

            // The merged file must not contain raw conflict markers
            QFile mergedFile(tempDir.absoluteFilePath("Cave 3006/notes/1.cwnote"));
            REQUIRE(mergedFile.open(QFile::ReadOnly));
            const auto mergedContent = QString::fromUtf8(mergedFile.readAll());
            CHECK_FALSE(mergedContent.contains(QStringLiteral("<<<<<<<")));
            CHECK_FALSE(mergedContent.contains(QStringLiteral("=======")));
            CHECK_FALSE(mergedContent.contains(QStringLiteral(">>>>>>>")));
            // resolveWithOurs picks our (renamed) version
            CHECK(mergedContent.contains(QStringLiteral("ours-version")));
        }
    }
}

TEST_CASE("GitRepository static head and diff helpers should work", "[GitRepository]")
{
    auto tempDir = TestUtilities::createUniqueTempDir();

    GitRepository repo;
    repo.setDirectory(tempDir);
    CHECK_NOTHROW(repo.initRepository());

    SECTION("headCommitOid should be empty when repository has no commits")
    {
        auto headResult = GitRepository::headCommitOid(tempDir.absolutePath());
        REQUIRE(!headResult.hasError());
        CHECK(headResult.value().isEmpty());
    }

    SECTION("headCommitMessage should be empty when repository has no commits")
    {
        auto messageResult = GitRepository::headCommitMessage(tempDir.absolutePath());
        REQUIRE(!messageResult.hasError());
        CHECK(messageResult.value().isEmpty());
    }

    Account account;
    account.setName("Sauce");
    account.setEmail("sauce@email.com");
    repo.setAccount(&account);

    {
        QFile file(tempDir.absoluteFilePath("alpha.txt"));
        REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate));
        file.write("alpha-1\n");
    }
    CHECK_NOTHROW(repo.commitAll("first", "first commit"));

    auto firstHeadResult = GitRepository::headCommitOid(tempDir.absolutePath());
    REQUIRE(!firstHeadResult.hasError());
    REQUIRE(!firstHeadResult.value().isEmpty());
    const QString firstHead = firstHeadResult.value();
    CHECK(firstHead.size() == 40);

    SECTION("headCommitMessage should return the most recent commit message")
    {
        auto messageResult = GitRepository::headCommitMessage(tempDir.absolutePath());
        REQUIRE(!messageResult.hasError());
        // commitAll(subject, description) stores "subject\n\ndescription"; strip trailing newline
        CHECK(messageResult.value().trimmed() == QStringLiteral("first\n\nfirst commit"));
    }

    SECTION("diffPathsBetweenCommits should include root commit files")
    {
        auto diffResult = GitRepository::diffPathsBetweenCommits(tempDir.absolutePath(), QString(), firstHead);
        REQUIRE(!diffResult.hasError());
        CHECK(diffResult.value().contains(QStringLiteral("alpha.txt")));
    }

    {
        QFile file(tempDir.absoluteFilePath("alpha.txt"));
        REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate));
        file.write("alpha-2\n");
    }

    REQUIRE(tempDir.mkpath(QStringLiteral("sub")));
    {
        QFile file(tempDir.absoluteFilePath("sub/beta.txt"));
        REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate));
        file.write("beta-1\n");
    }
    CHECK_NOTHROW(repo.commitAll("second", "second commit"));

    auto secondHeadResult = GitRepository::headCommitOid(tempDir.absolutePath());
    REQUIRE(!secondHeadResult.hasError());
    REQUIRE(!secondHeadResult.value().isEmpty());
    const QString secondHead = secondHeadResult.value();
    CHECK(secondHead.size() == 40);
    CHECK(secondHead != firstHead);

    SECTION("headCommitMessage should update to the latest commit after a new commit")
    {
        auto messageResult = GitRepository::headCommitMessage(tempDir.absolutePath());
        REQUIRE(!messageResult.hasError());
        CHECK(messageResult.value().trimmed() == QStringLiteral("second\n\nsecond commit"));
    }

    SECTION("diffPathsBetweenCommits should include changed paths between commits")
    {
        auto diffResult = GitRepository::diffPathsBetweenCommits(tempDir.absolutePath(), firstHead, secondHead);
        REQUIRE(!diffResult.hasError());
        CHECK(diffResult.value().contains(QStringLiteral("alpha.txt")));
        CHECK(diffResult.value().contains(QStringLiteral("sub/beta.txt")));
    }

    SECTION("fileContentAtCommit should read file contents for a commit path")
    {
        auto firstContentResult = GitRepository::fileContentAtCommit(tempDir.absolutePath(),
                                                                     firstHead,
                                                                     QStringLiteral("alpha.txt"));
        REQUIRE(!firstContentResult.hasError());
        CHECK(firstContentResult.value() == QByteArray("alpha-1\n"));

        auto secondContentResult = GitRepository::fileContentAtCommit(tempDir.absolutePath(),
                                                                      secondHead,
                                                                      QStringLiteral("alpha.txt"));
        REQUIRE(!secondContentResult.hasError());
        CHECK(secondContentResult.value() == QByteArray("alpha-2\n"));
    }

    SECTION("fileContentAtCommit should return empty for missing commit path")
    {
        auto missingResult = GitRepository::fileContentAtCommit(tempDir.absolutePath(),
                                                                secondHead,
                                                                QStringLiteral("missing.txt"));
        REQUIRE(!missingResult.hasError());
        CHECK(missingResult.value().isEmpty());
    }

    SECTION("mergeBaseCommitOid should resolve the common ancestor")
    {
        auto mergeBaseResult = GitRepository::mergeBaseCommitOid(tempDir.absolutePath(), firstHead, secondHead);
        REQUIRE(!mergeBaseResult.hasError());
        CHECK(mergeBaseResult.value() == firstHead);
    }

    SECTION("aheadBehindCommitCounts should report forward and reverse commit deltas")
    {
        auto forwardResult = GitRepository::aheadBehindCommitCounts(tempDir.absolutePath(),
                                                                    secondHead,
                                                                    firstHead);
        REQUIRE(!forwardResult.hasError());
        CHECK(forwardResult.value().ahead == 1);
        CHECK(forwardResult.value().behind == 0);

        auto reverseResult = GitRepository::aheadBehindCommitCounts(tempDir.absolutePath(),
                                                                    firstHead,
                                                                    secondHead);
        REQUIRE(!reverseResult.hasError());
        CHECK(reverseResult.value().ahead == 0);
        CHECK(reverseResult.value().behind == 1);
    }

    SECTION("aheadBehindCommitCounts should be zero when comparing the same commit")
    {
        auto countsResult = GitRepository::aheadBehindCommitCounts(tempDir.absolutePath(),
                                                                   secondHead,
                                                                   secondHead);
        REQUIRE(!countsResult.hasError());
        CHECK(countsResult.value().ahead == 0);
        CHECK(countsResult.value().behind == 0);
    }

    SECTION("aheadBehindCommitCounts should return error for invalid refs")
    {
        auto invalidResult = GitRepository::aheadBehindCommitCounts(tempDir.absolutePath(),
                                                                    QStringLiteral("missing-local-ref"),
                                                                    secondHead);
        CHECK(invalidResult.hasError());
    }

    SECTION("diffPathsBetweenCommits should be empty when before and after are equal")
    {
        auto diffResult = GitRepository::diffPathsBetweenCommits(tempDir.absolutePath(), secondHead, secondHead);
        REQUIRE(!diffResult.hasError());
        CHECK(diffResult.value().isEmpty());
    }

    SECTION("diffPathsBetweenCommits should return an error for invalid oid")
    {
        auto diffResult = GitRepository::diffPathsBetweenCommits(tempDir.absolutePath(),
                                                                 firstHead,
                                                                 QStringLiteral("invalid-oid"));
        CHECK(diffResult.hasError());
    }

    SECTION("mergeBaseCommitOid should return empty when no merge-base is found")
    {
        auto mergeBaseResult = GitRepository::mergeBaseCommitOid(tempDir.absolutePath(),
                                                                 firstHead,
                                                                 QStringLiteral("0000000000000000000000000000000000000000"));
        if (!mergeBaseResult.hasError()) {
            CHECK(mergeBaseResult.value().isEmpty());
        } else {
            CHECK(!mergeBaseResult.errorMessage().isEmpty());
        }
    }
}

TEST_CASE("GitRepository push should classify remote-advance rejection", "[GitRepository]")
{
    auto tempDir = TestUtilities::createUniqueTempDir();
    const QString remotePath = tempDir.absoluteFilePath(QStringLiteral("remote-push-rejection.git"));
    const QString authorPath = tempDir.absoluteFilePath(QStringLiteral("author"));
    const QString peerPath = tempDir.absoluteFilePath(QStringLiteral("peer"));

    git_repository* remoteRepo = nullptr;
    REQUIRE(git_repository_init(&remoteRepo, remotePath.toLocal8Bit().constData(), 1) == GIT_OK);
    REQUIRE(remoteRepo != nullptr);
    git_repository_free(remoteRepo);

    REQUIRE(QDir().mkpath(authorPath));

    Account account;
    account.setName(QStringLiteral("Tester"));
    account.setEmail(QStringLiteral("tester@example.com"));

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.initRepository();
    author.setAccount(&account);
    author.addRemote(QStringLiteral("origin"), QUrl::fromLocalFile(remotePath));

    auto writeState = [](const QString& directoryPath, const QString& contents) {
        QFile file(QDir(directoryPath).absoluteFilePath(QStringLiteral("state.txt")));
        REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate | QFile::Text));
        file.write(contents.toUtf8());
    };

    writeState(authorPath, QStringLiteral("author-initial\n"));
    CHECK_NOTHROW(author.commitAll(QStringLiteral("Initial"), QStringLiteral("author initial commit")));
    auto initialPushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(initialPushFuture, defaultTimeout));
    REQUIRE(!initialPushFuture.result().hasError());

    GitRepository peer;
    peer.setDirectory(QDir(peerPath));
    peer.setAccount(&account);
    waitForClone(peer.clone(QUrl::fromLocalFile(remotePath)));

    writeState(peerPath, QStringLiteral("peer-advance\n"));
    CHECK_NOTHROW(peer.commitAll(QStringLiteral("Peer Advance"), QStringLiteral("advance remote tip")));
    auto peerPushFuture = peer.push();
    REQUIRE(AsyncFuture::waitForFinished(peerPushFuture, defaultTimeout));
    REQUIRE(!peerPushFuture.result().hasError());

    writeState(authorPath, QStringLiteral("author-diverge\n"));
    CHECK_NOTHROW(author.commitAll(QStringLiteral("Author Diverge"), QStringLiteral("local divergent commit")));
    auto rejectedPushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(rejectedPushFuture, defaultTimeout));
    const ResultBase rejectedPushResult = rejectedPushFuture.result();
    REQUIRE(rejectedPushResult.hasError());
    CHECK(rejectedPushResult.errorCode()
          == static_cast<int>(GitRepository::GitErrorCode::PushRejectedByRemoteAdvance));
    CHECK(GitRepository::isPushRejectedByRemoteAdvanceError(rejectedPushResult.errorCode()));
}

TEST_CASE("GitRepository remoteAheadBehindCommitCounts should read advertised remote tips", "[GitRepository]")
{
    auto tempDir = TestUtilities::createUniqueTempDir();
    const QString remotePath = tempDir.absoluteFilePath(QStringLiteral("remote-ahead-behind.git"));
    const QString authorPath = tempDir.absoluteFilePath(QStringLiteral("author"));
    const QString peerPath = tempDir.absoluteFilePath(QStringLiteral("peer"));

    git_repository* remoteRepo = nullptr;
    REQUIRE(git_repository_init(&remoteRepo, remotePath.toLocal8Bit().constData(), 1) == GIT_OK);
    REQUIRE(remoteRepo != nullptr);
    git_repository_free(remoteRepo);

    REQUIRE(QDir().mkpath(authorPath));

    Account account;
    account.setName(QStringLiteral("Tester"));
    account.setEmail(QStringLiteral("tester@example.com"));

    GitRepository author;
    author.setDirectory(QDir(authorPath));
    author.initRepository();
    author.setAccount(&account);
    author.addRemote(QStringLiteral("origin"), QUrl::fromLocalFile(remotePath));

    auto writeState = [](const QString& directoryPath, const QString& contents) {
        QFile file(QDir(directoryPath).absoluteFilePath(QStringLiteral("state.txt")));
        REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate | QFile::Text));
        file.write(contents.toUtf8());
    };

    writeState(authorPath, QStringLiteral("author-initial\n"));
    CHECK_NOTHROW(author.commitAll(QStringLiteral("Initial"), QStringLiteral("author initial commit")));
    auto initialPushFuture = author.push();
    REQUIRE(AsyncFuture::waitForFinished(initialPushFuture, defaultTimeout));
    REQUIRE(!initialPushFuture.result().hasError());

    GitRepository peer;
    peer.setDirectory(QDir(peerPath));
    peer.setAccount(&account);
    waitForClone(peer.clone(QUrl::fromLocalFile(remotePath)));

    writeState(peerPath, QStringLiteral("peer-advance\n"));
    CHECK_NOTHROW(peer.commitAll(QStringLiteral("Peer Advance"), QStringLiteral("advance remote tip")));
    auto peerPushFuture = peer.push();
    REQUIRE(AsyncFuture::waitForFinished(peerPushFuture, defaultTimeout));
    REQUIRE(!peerPushFuture.result().hasError());

    SECTION("without fetch, local repository still sees remote behind/ahead from remote advertisement")
    {
        auto remoteCountsFuture = author.remoteAheadBehindCommitCounts();
        REQUIRE(AsyncFuture::waitForFinished(remoteCountsFuture, defaultTimeout));
        const auto remoteCountsResult = remoteCountsFuture.result();
        INFO("Remote ahead/behind error:" << remoteCountsResult.errorMessage().toStdString());
        REQUIRE(!remoteCountsResult.hasError());
        CHECK(remoteCountsResult.value().ahead == 0);
        CHECK(remoteCountsResult.value().behind == 1);
    }

    SECTION("diverged history reports both ahead and behind")
    {
        writeState(authorPath, QStringLiteral("author-diverge\n"));
        CHECK_NOTHROW(author.commitAll(QStringLiteral("Author Diverge"), QStringLiteral("local divergent commit")));

        auto remoteCountsFuture = author.remoteAheadBehindCommitCounts();
        REQUIRE(AsyncFuture::waitForFinished(remoteCountsFuture, defaultTimeout));
        const auto remoteCountsResult = remoteCountsFuture.result();
        INFO("Remote ahead/behind error:" << remoteCountsResult.errorMessage().toStdString());
        REQUIRE(!remoteCountsResult.hasError());
        CHECK(remoteCountsResult.value().ahead == 1);
        CHECK(remoteCountsResult.value().behind == 1);
    }

    SECTION("missing remote branch returns error")
    {
        auto missingBranchFuture = author.remoteAheadBehindCommitCounts(QStringLiteral("origin"),
                                                                        QStringLiteral("missing-branch"));
        REQUIRE(AsyncFuture::waitForFinished(missingBranchFuture, defaultTimeout));
        CHECK(missingBranchFuture.result().hasError());
    }
}

TEST_CASE("GitRepository remoteAheadBehindCommitCounts with empty HTTPS token returns HttpAuthFailed", "[GitRepository]")
{
    // Spin up a local TCP server that always responds HTTP 401.
    // This exercises the credential-callback path without needing a real remote.
    QTcpServer httpServer;
    REQUIRE(httpServer.listen(QHostAddress::LocalHost, 0));
    const quint16 port = httpServer.serverPort();

    QObject::connect(&httpServer, &QTcpServer::newConnection, [&httpServer]() {
        QTcpSocket* socket = httpServer.nextPendingConnection();
        QObject::connect(socket, &QTcpSocket::readyRead, socket, [socket]() {
            socket->readAll(); // discard the request
            socket->write("HTTP/1.1 401 Unauthorized\r\n"
                          "WWW-Authenticate: Basic realm=\"git\"\r\n"
                          "Content-Length: 0\r\n"
                          "Connection: close\r\n"
                          "\r\n");
            socket->flush();
            socket->disconnectFromHost();
        });
    });

    auto tempDir = TestUtilities::createUniqueTempDir();
    const QString localPath = tempDir.absoluteFilePath(QStringLiteral("repo"));
    REQUIRE(QDir().mkpath(localPath));

    Account account;
    account.setName(QStringLiteral("Tester"));
    account.setEmail(QStringLiteral("tester@example.com"));

    GitRepository repo;
    repo.setDirectory(QDir(localPath));
    repo.initRepository();
    repo.setAccount(&account);
    repo.addRemote(QStringLiteral("origin"),
                   QUrl(QStringLiteral("http://127.0.0.1:%1/repo.git").arg(port)));

    QFile file(QDir(localPath).absoluteFilePath(QStringLiteral("state.txt")));
    REQUIRE(file.open(QFile::WriteOnly));
    file.write("initial");
    file.close();
    CHECK_NOTHROW(repo.commitAll(QStringLiteral("Initial"), QStringLiteral("initial commit")));

    // No credentials set — empty token must produce HttpAuthFailed, not an SSL error
    auto future = repo.remoteAheadBehindCommitCounts();
    REQUIRE(AsyncFuture::waitForFinished(future, defaultTimeout));
    const auto result = future.result();
    INFO("Error message: " << result.errorMessage().toStdString());
    REQUIRE(result.hasError());
    CHECK(result.errorCode() == static_cast<int>(GitRepository::GitErrorCode::HttpAuthFailed));
}

TEST_CASE("GitRepository pullRebaseOrMerge should prefer rebase and fallback to merge on conflicts", "[GitRepository]")
{
    auto tempDir = TestUtilities::createUniqueTempDir();
    const QString remotePath = tempDir.absoluteFilePath(QStringLiteral("remote-pull-rebase-or-merge.git"));
    const QString authorPath = tempDir.absoluteFilePath(QStringLiteral("author"));
    const QString peerPath = tempDir.absoluteFilePath(QStringLiteral("peer"));

    git_repository* remoteRepo = nullptr;
    REQUIRE(git_repository_init(&remoteRepo, remotePath.toLocal8Bit().constData(), 1) == GIT_OK);
    REQUIRE(remoteRepo != nullptr);
    git_repository_free(remoteRepo);

    REQUIRE(QDir().mkpath(authorPath));

    Account account;
    account.setName(QStringLiteral("Tester"));
    account.setEmail(QStringLiteral("tester@example.com"));

    auto writeFile = [](const QString& directoryPath, const QString& relativePath, const QByteArray& contents) {
        const QString absolutePath = QDir(directoryPath).absoluteFilePath(relativePath);
        QFileInfo info(absolutePath);
        if (!info.dir().exists()) {
            REQUIRE(info.dir().mkpath(QStringLiteral(".")));
        }

        QFile file(absolutePath);
        REQUIRE(file.open(QFile::WriteOnly | QFile::Truncate | QFile::Text));
        REQUIRE(file.write(contents) == contents.size());
        file.close();
    };

    auto readFile = [](const QString& directoryPath, const QString& relativePath) {
        QFile file(QDir(directoryPath).absoluteFilePath(relativePath));
        REQUIRE(file.open(QFile::ReadOnly | QFile::Text));
        return file.readAll();
    };

    auto headOid = [](const QString& directoryPath) {
        git_repository* repo = nullptr;
        REQUIRE(git_repository_open(&repo, directoryPath.toLocal8Bit().constData()) == GIT_OK);
        auto repoGuard = qScopeGuard([&repo]() {
            if (repo) {
                git_repository_free(repo);
            }
        });

        git_reference* headRef = nullptr;
        REQUIRE(git_repository_head(&headRef, repo) == GIT_OK);
        auto headGuard = qScopeGuard([&headRef]() {
            if (headRef) {
                git_reference_free(headRef);
            }
        });

        const git_oid* oid = git_reference_target(headRef);
        REQUIRE(oid != nullptr);
        return *oid;
    };

    auto headParentCount = [](const QString& directoryPath) {
        git_repository* repo = nullptr;
        REQUIRE(git_repository_open(&repo, directoryPath.toLocal8Bit().constData()) == GIT_OK);
        auto repoGuard = qScopeGuard([&repo]() {
            if (repo) {
                git_repository_free(repo);
            }
        });

        git_reference* headRef = nullptr;
        REQUIRE(git_repository_head(&headRef, repo) == GIT_OK);
        auto headGuard = qScopeGuard([&headRef]() {
            if (headRef) {
                git_reference_free(headRef);
            }
        });

        const git_oid* oid = git_reference_target(headRef);
        REQUIRE(oid != nullptr);

        git_commit* commit = nullptr;
        REQUIRE(git_commit_lookup(&commit, repo, oid) == GIT_OK);
        auto commitGuard = qScopeGuard([&commit]() {
            if (commit) {
                git_commit_free(commit);
            }
        });

        return git_commit_parentcount(commit);
    };

    SECTION("clean diverged history rebases without merge commit")
    {
        GitRepository author;
        author.setDirectory(QDir(authorPath));
        author.initRepository();
        author.setAccount(&account);
        author.addRemote(QStringLiteral("origin"), QUrl::fromLocalFile(remotePath));

        writeFile(authorPath, QStringLiteral("state.txt"), QByteArray("base\n"));
        CHECK_NOTHROW(author.commitAll(QStringLiteral("Initial"), QStringLiteral("baseline")));
        auto initialPushFuture = author.push();
        REQUIRE(AsyncFuture::waitForFinished(initialPushFuture, defaultTimeout));
        REQUIRE(!initialPushFuture.result().hasError());

        GitRepository peer;
        peer.setDirectory(QDir(peerPath));
        peer.setAccount(&account);
        waitForClone(peer.clone(QUrl::fromLocalFile(remotePath)));

        writeFile(authorPath, QStringLiteral("author-only.txt"), QByteArray("author change\n"));
        CHECK_NOTHROW(author.commitAll(QStringLiteral("Author Local"), QStringLiteral("local change")));
        const git_oid authorHeadBeforePull = headOid(authorPath);

        writeFile(peerPath, QStringLiteral("peer-only.txt"), QByteArray("peer change\n"));
        CHECK_NOTHROW(peer.commitAll(QStringLiteral("Peer Remote"), QStringLiteral("remote change")));
        auto peerPushFuture = peer.push();
        REQUIRE(AsyncFuture::waitForFinished(peerPushFuture, defaultTimeout));
        REQUIRE(!peerPushFuture.result().hasError());
        const git_oid remoteHeadBeforePull = headOid(peerPath);

        auto pullFuture = author.pullRebaseOrMerge();
        REQUIRE(AsyncFuture::waitForFinished(pullFuture, defaultTimeout));
        INFO("pullRebaseOrMerge error:" << pullFuture.result().errorMessage().toStdString());
        REQUIRE(!pullFuture.result().hasError());
        CHECK(pullFuture.result().value().state() == GitRepository::MergeResult::Rebased);

        const git_oid authorHeadAfterPull = headOid(authorPath);
        CHECK(git_oid_cmp(&authorHeadAfterPull, &authorHeadBeforePull) != 0);
        CHECK(git_oid_cmp(&authorHeadAfterPull, &remoteHeadBeforePull) != 0);
        CHECK(headParentCount(authorPath) == 1);
        CHECK(readFile(authorPath, QStringLiteral("author-only.txt")) == QByteArray("author change\n"));
        CHECK(readFile(authorPath, QStringLiteral("peer-only.txt")) == QByteArray("peer change\n"));
    }

    SECTION("rebase conflict falls back to merge and keeps ours")
    {
        GitRepository author;
        author.setDirectory(QDir(authorPath));
        author.initRepository();
        author.setAccount(&account);
        author.addRemote(QStringLiteral("origin"), QUrl::fromLocalFile(remotePath));

        writeFile(authorPath, QStringLiteral("shared.txt"), QByteArray("base\n"));
        CHECK_NOTHROW(author.commitAll(QStringLiteral("Initial"), QStringLiteral("baseline")));
        auto initialPushFuture = author.push();
        REQUIRE(AsyncFuture::waitForFinished(initialPushFuture, defaultTimeout));
        REQUIRE(!initialPushFuture.result().hasError());

        GitRepository peer;
        peer.setDirectory(QDir(peerPath));
        peer.setAccount(&account);
        waitForClone(peer.clone(QUrl::fromLocalFile(remotePath)));

        writeFile(authorPath, QStringLiteral("shared.txt"), QByteArray("ours\n"));
        CHECK_NOTHROW(author.commitAll(QStringLiteral("Author Ours"), QStringLiteral("local conflicting change")));

        writeFile(peerPath, QStringLiteral("shared.txt"), QByteArray("theirs\n"));
        CHECK_NOTHROW(peer.commitAll(QStringLiteral("Peer Theirs"), QStringLiteral("remote conflicting change")));
        auto peerPushFuture = peer.push();
        REQUIRE(AsyncFuture::waitForFinished(peerPushFuture, defaultTimeout));
        REQUIRE(!peerPushFuture.result().hasError());

        auto pullFuture = author.pullRebaseOrMerge();
        REQUIRE(AsyncFuture::waitForFinished(pullFuture, defaultTimeout));
        INFO("pullRebaseOrMerge error:" << pullFuture.result().errorMessage().toStdString());
        REQUIRE(!pullFuture.result().hasError());
        CHECK(pullFuture.result().value().state() == GitRepository::MergeResult::MergeCommitCreated);
        CHECK(headParentCount(authorPath) == 2);
        CHECK(readFile(authorPath, QStringLiteral("shared.txt")) == QByteArray("ours\n"));
    }
}


TEST_CASE("GitRepository testRemoteConnection should work", "[GitRepository]") {

    auto errorFuture = GitRepository::testRemoteConnection(QUrl("ssh://git@github.com/vpicaver/surfacewhere-testData.git"));
    REQUIRE(AsyncFuture::waitForFinished(errorFuture, 2000));

    CHECK(errorFuture.result()
          .toStdString()
          ==
          "");

    errorFuture = GitRepository::testRemoteConnection(QUrl("xyz"));
    REQUIRE(AsyncFuture::waitForFinished(errorFuture, 2000));
    CHECK(errorFuture.result()
          .toStdString()
          ==
          "unsupported URL protocol");

    errorFuture = GitRepository::testRemoteConnection(QUrl(""));
    REQUIRE(AsyncFuture::waitForFinished(errorFuture, 2000));
    CHECK(errorFuture.result()
          .toStdString()
          ==
          "cannot set empty URL");

    errorFuture = GitRepository::testRemoteConnection(QUrl("ssh://git@github.com/vpicaver"));
    REQUIRE(AsyncFuture::waitForFinished(errorFuture, 2000));
    CHECK(errorFuture.result()
          ==
          "ERROR: Repository not found.");

}

TEST_CASE("GitRepository testRemoteConnectionDetailed should report transport and lfs states", "[GitRepository]") {
    auto reportFuture = GitRepository::testRemoteConnectionDetailed(QUrl("xyz"), true);
    REQUIRE(AsyncFuture::waitForFinished(reportFuture, 2000));
    const auto report = reportFuture.result();
    CHECK(!report.transportOk);
    CHECK(report.transportErrorMessage.toStdString() == "unsupported URL protocol");
    CHECK(!report.lfsProbeAttempted);

    reportFuture = GitRepository::testRemoteConnectionDetailed(QUrl(""), true);
    REQUIRE(AsyncFuture::waitForFinished(reportFuture, 2000));
    const auto emptyUrlReport = reportFuture.result();
    CHECK(!emptyUrlReport.transportOk);
    CHECK(emptyUrlReport.transportErrorMessage.toStdString() == "cannot set empty URL");
}

TEST_CASE("GitRepository addRemote raw-string overload should work correctly", "[GitRepository]") {
    auto tempDir = TestUtilities::createUniqueTempDir();
    const QString repoPath = tempDir.absoluteFilePath(QStringLiteral("repo"));

    REQUIRE(QDir().mkpath(repoPath));

    GitRepository repo;
    repo.setDirectory(QDir(repoPath));
    repo.initRepository();

    SECTION("Adding a remote with a local file URL string succeeds") {
        const QString remotePath = tempDir.absoluteFilePath(QStringLiteral("remote.git"));

        git_repository* bareRepo = nullptr;
        REQUIRE(git_repository_init(&bareRepo, remotePath.toLocal8Bit().constData(), 1) == GIT_OK);
        git_repository_free(bareRepo);

        QSignalSpy remotesChangedSpy(&repo, &GitRepository::remotesChanged);
        const QString error = repo.addRemote(QStringLiteral("origin"), QUrl::fromLocalFile(remotePath).toString());
        CHECK(error.isEmpty());
        CHECK(remotesChangedSpy.size() == 1);

        const auto remotes = repo.remotes();
        REQUIRE(remotes.size() == 1);
        CHECK(remotes.at(0).name() == QStringLiteral("origin"));
    }

    SECTION("Adding a remote with SSH SCP-syntax URL succeeds") {
        // QUrl cannot round-trip git@host:path SCP syntax; verify the raw-string
        // overload stores the URL verbatim by querying libgit2 directly.
        const QString scpUrl = QStringLiteral("git@github.com:vpicaver/libgit2-test.git");

        QSignalSpy remotesChangedSpy(&repo, &GitRepository::remotesChanged);
        const QString error = repo.addRemote(QStringLiteral("origin"), scpUrl);
        CHECK(error.isEmpty());
        CHECK(remotesChangedSpy.size() == 1);

        const auto remotes = repo.remotes();
        REQUIRE(remotes.size() == 1);
        CHECK(remotes.at(0).name() == QStringLiteral("origin"));

        // GitRemoteInfo stores QUrl which cannot round-trip SCP syntax; verify
        // the raw URL is preserved by opening the repo via libgit2 directly.
        git_repository* rawRepo = nullptr;
        REQUIRE(git_repository_open(&rawRepo, repoPath.toLocal8Bit().constData()) == GIT_OK);
        git_remote* remote = nullptr;
        REQUIRE(git_remote_lookup(&remote, rawRepo, "origin") == GIT_OK);
        CHECK(QString::fromUtf8(git_remote_url(remote)) == scpUrl);
        git_remote_free(remote);
        git_repository_free(rawRepo);
    }

    SECTION("Adding a duplicate remote name returns a non-empty error string") {
        const QString scpUrl = QStringLiteral("git@github.com:vpicaver/libgit2-test.git");
        REQUIRE(repo.addRemote(QStringLiteral("origin"), scpUrl).isEmpty());

        const QString error = repo.addRemote(QStringLiteral("origin"), scpUrl);
        CHECK_FALSE(error.isEmpty());
    }
}

TEST_CASE("GitRepository clone should report progress", "[GitRepository]") {
    QDir cloneDir("clone-test");

    INFO("Dir:" << QDir::toNativeSeparators(cloneDir.absolutePath()).toStdString());
    CHECK(cloneDir.removeRecursively());

    GitRepository repository;
    repository.setDirectory(cloneDir);

    auto future = repository.clone(QUrl("ssh://git@github.com/vpicaver/QQuickGit.git"));

    //Much bigger repository
//    auto future = repository.clone(QUrl("ssh://git@gitlab.com/caves-org/btcp/gros-vertre-east.git"));
    int count = 0;

    CHECK(ProgressState::fromJson(future.progressText()).progress() < 1.0);

    AsyncFuture::observe(future).onProgress([future, &count](){
        count++;
//        qDebug() << "p:" << future.progressValue() << future.progressMaximum() << future.progressText();
//        auto progress = ProgressState::fromJson(future.progressText());
//        qDebug() << "progress:" << (100.0 * progress.progress()) << progress.text();
    });

    waitForClone(future, 10 * 1000);

    CHECK(count > 0);
    INFO("Json:" << future.progressText().toStdString());
    CHECK(ProgressState::fromJson(future.progressText()).progress() == 1.0);
}

TEST_CASE("GitRepository::hasMissingLfsFiles", "[GitRepository][lfs]") {
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    // Valid LFS pointer content referencing a non-existent object.
    LfsPointer pointer;
    pointer.oid = QStringLiteral("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    pointer.size = 42;
    const QByteArray pointerText = pointer.toPointerText();
    REQUIRE(!pointerText.isEmpty());

    QObject* ctx = QCoreApplication::instance();

    SECTION("returns false for a non-repository directory") {
        const QDir nonRepo(tempDir.filePath(QStringLiteral("not-a-repo")));
        REQUIRE(QDir().mkpath(nonRepo.absolutePath()));

        auto future = GitRepository::hasMissingLfsFiles(nonRepo, ctx);
        REQUIRE(AsyncFuture::waitForFinished(future, 5000));
        CHECK(future.result() == false);
    }

    SECTION("returns false when no LFS pointer files exist") {
        const QDir repoDir(tempDir.filePath(QStringLiteral("clean-repo")));
        REQUIRE(QDir().mkpath(repoDir.absolutePath()));

        GitRepository repo;
        repo.setDirectory(repoDir);
        repo.initRepository();

        // Write a plain text file — not an LFS pointer.
        QFile f(repoDir.filePath(QStringLiteral("notes.txt")));
        REQUIRE(f.open(QIODevice::WriteOnly));
        f.write("just some text\n");
        f.close();

        auto future = GitRepository::hasMissingLfsFiles(repoDir, ctx);
        REQUIRE(AsyncFuture::waitForFinished(future, 5000));
        CHECK(future.result() == false);
    }

    SECTION("returns true when an LFS pointer file has no backing object") {
        const QDir repoDir(tempDir.filePath(QStringLiteral("missing-obj-repo")));
        REQUIRE(QDir().mkpath(repoDir.absolutePath()));

        GitRepository repo;
        repo.setDirectory(repoDir);
        repo.initRepository();

        // Write a pointer file to the working tree without storing the object.
        QFile f(repoDir.filePath(QStringLiteral("asset.png")));
        REQUIRE(f.open(QIODevice::WriteOnly));
        f.write(pointerText);
        f.close();

        auto future = GitRepository::hasMissingLfsFiles(repoDir, ctx);
        REQUIRE(AsyncFuture::waitForFinished(future, 5000));
        CHECK(future.result() == true);
    }

    SECTION("returns false when the LFS object is present in the store") {
        const QDir repoDir(tempDir.filePath(QStringLiteral("hydrated-repo")));
        REQUIRE(QDir().mkpath(repoDir.absolutePath()));

        git_repository* rawRepo = nullptr;
        REQUIRE(git_repository_init(&rawRepo, repoDir.absolutePath().toLocal8Bit().constData(), 0) == GIT_OK);
        const QString gitDirPath = QDir(QString::fromUtf8(git_repository_path(rawRepo))).absolutePath();
        git_repository_free(rawRepo);

        // Write the pointer file to the working tree.
        QFile f(repoDir.filePath(QStringLiteral("asset.png")));
        REQUIRE(f.open(QIODevice::WriteOnly));
        f.write(pointerText);
        f.close();

        // Store a dummy object so the pointer is considered hydrated.
        const QString objectPath = LfsStore::objectPath(gitDirPath, pointer.oid);
        REQUIRE(QDir().mkpath(QFileInfo(objectPath).absolutePath()));
        QFile obj(objectPath);
        REQUIRE(obj.open(QIODevice::WriteOnly));
        obj.write(QByteArray(static_cast<int>(pointer.size), 'x'));
        obj.close();

        auto future = GitRepository::hasMissingLfsFiles(repoDir, ctx);
        REQUIRE(AsyncFuture::waitForFinished(future, 5000));
        CHECK(future.result() == false);
    }
}
