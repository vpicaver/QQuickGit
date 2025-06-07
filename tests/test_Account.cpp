//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our inculdes
#include "Account.h"
#include <SignalSpyChecker.h>
using namespace SignalSpyChecker;

TEST_CASE("Account should have a openSSH RSA public key", "[Account]") {
    Account account;
    auto key = account.publicKey();

    CHECK(key.isEmpty() == false);
    CHECK(key.left(7) == "ssh-rsa");
}

TEST_CASE("Account should return a valid user AuthorizedKeyModel::User", "[Account]") {
    Account account;
    auto spyChecker = Constant::makeChecker(&account);

    account.setName("sauce");
    account.setEmail("sauce@gmail.com");

    spyChecker[spyChecker.findSpy(&Account::nameChanged)]++;
    spyChecker[spyChecker.findSpy(&Account::emailChanged)]++;
    spyChecker[spyChecker.findSpy(&Account::sshUserChanged)]+=2;
    spyChecker[spyChecker.findSpy(&Account::isValidChanged)]+=2;
    spyChecker.checkSpies();

    auto user = account.sshUser();
    CHECK(user.isValid());
    CHECK(user.name() == "sauce");
    CHECK(user.email() == "sauce@gmail.com");
    CHECK(!user.comment().isEmpty());
    CHECK(!user.key().isEmpty());



}
