//Catch includes
#include <catch2/catch_test_macros.hpp>

//libgit2
#include "git2.h"

//Our inculdes
#include "GitRepository.h"
#include "Account.h"
#include "TestUtilities.h"
#include "ProgressState.h"

//Qt includes
#include <QDir>
#include <QDebug>
#include <QSignalSpy>
#include <QFuture>

//Std includes
#include <iostream>

//Async include
#include "asyncfuture.h"

//Monad
#include "Monad/Result.h"
using namespace Monad;

const int defaultTimeout = 10000;

auto waitForClone(QFuture<ResultBase> future, int timeout = defaultTimeout) {
    REQUIRE(AsyncFuture::waitForFinished(future, timeout));
    INFO("Clone error:" << future.result().errorMessage().toStdString() << "code:" << future.result().errorCode());
    CHECK(!future.result().hasError());
}

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
            file.open(QFile::WriteOnly);
            file.write("Hello world!\n");
        }

        repository.checkStatus();
        CHECK(repository.modifiedFileCount() == 1);
        CHECK(modifiedCountChangedSpy.size() == 1);

        {
            QFile file(cloneDir.absoluteFilePath("test2.txt"));
            file.open(QFile::WriteOnly);
            file.write("Hello world! 2\n");
        }

        repository.checkStatus();
        CHECK(repository.modifiedFileCount() == 2);
        CHECK(modifiedCountChangedSpy.size() == 2);

        SECTION("Status should ignore files in .gitignore") {
            // Add *.ignore pattern to .gitignore
            {
                QFile file(cloneDir.absoluteFilePath(".gitignore"));
                file.open(QFile::WriteOnly);
                file.write("*.ignore\n");
                qDebug() << "Ignore file:" << file.fileName();
            }

            // Create an .ignore file
            for(int i = 0; i < 10; i++) {
                QFile file(cloneDir.absoluteFilePath(QString("test%1.ignore").arg(i)));
                file.open(QFile::WriteOnly);
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
                    file.open(QFile::Append);
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
                        file.open(QFile::WriteOnly);
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
                        file.open(QFile::WriteOnly);
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
                        file.open(QFile::WriteOnly);
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
                    file.open(QFile::WriteOnly);
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
                        file.open(QFile::WriteOnly);
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
                        file.open(QFile::WriteOnly);
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
        CHECK_NOTHROW(repository.createBranch("testBranch"));

        Account account;
        account.setName("Test name");
        account.setEmail("test@email.com");

        repository.setAccount(&account);

        {
            QFile file(cloneDir.absoluteFilePath("test8.txt"));
            file.open(QFile::WriteOnly);
            file.write("Hello world :D :D!\n");
        }

        CHECK_NOTHROW(repository.commitAll("testBranch", ""));

        auto pushFuture = repository.push();
        AsyncFuture::waitForFinished(pushFuture, defaultTimeout);
        INFO("Force push error:" << pushFuture.result().errorMessage().toStdString());
        REQUIRE(!pushFuture.result().hasError());

        auto deleteFuture = repository.deleteBranchRemote(repository.headBranchName());
        AsyncFuture::waitForFinished(deleteFuture, defaultTimeout);
        INFO("Delete Future Error:" << deleteFuture.result().errorMessage().toStdString());
        REQUIRE(!deleteFuture.result().hasError());

        CHECK(!repository.remoteBranchExists("origin/testBranch"));
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
        file.open(QFile::WriteOnly);
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
            file.open(QFile::WriteOnly);
            file.write("Hello world 2!\n");
        }

        CHECK_NOTHROW(repo.commitAll("test1", "2 test commit"));

        SECTION("Fast forward") {
            CHECK_NOTHROW(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            GitRepository::MergeResult result;
            CHECK_NOTHROW(result = repo.merge({"testBranch"}));

            CHECK(result.state() == GitRepository::MergeResult::FastForward);
        }

        SECTION("Simple merge, no conflicts") {
            CHECK_NOTHROW(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            {
                QFile file(tempDir.absoluteFilePath("test3.txt"));
                file.open(QFile::WriteOnly);
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
                file.open(QFile::WriteOnly);
                file.write(":D Hello world!\n");
            }

            repo.commitAll("test2", "3 test commit");

            CHECK_NOTHROW(repo.checkout("refs/heads/master"));
            CHECK(repo.headBranchName().toStdString() == "master");

            {
                QFile file(tempDir.absoluteFilePath("test.txt"));
                file.open(QFile::WriteOnly);
                file.write(":( Hello world!\n");
            }

            repo.commitAll("test3", "4 test commit");

            GitRepository::MergeResult result;
            CHECK_NOTHROW(result = repo.merge({"testBranch"}));

            CHECK(result.state() == GitRepository::MergeResult::MergeCommitCreated);
            QFile file(tempDir.absoluteFilePath("test.txt"));
            file.open(QFile::ReadOnly);
            auto fileContent = file.readAll();
            CHECK(fileContent.toStdString() == ":( Hello world!\n");
        }
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

TEST_CASE("GitRepository clone should report progress", "[GitRepository]") {
    QDir cloneDir("clone-test");

    INFO("Dir:" << QDir::toNativeSeparators(cloneDir.absolutePath()).toStdString());
    CHECK(cloneDir.removeRecursively());

    GitRepository repository;
    repository.setDirectory(cloneDir);

    auto future = repository.clone(QUrl("ssh://git@github.com/vpicaver/marbleRange.git"));

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
