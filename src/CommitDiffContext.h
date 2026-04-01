#ifndef COMMITDIFFCONTEXT_H
#define COMMITDIFFCONTEXT_H

//Qt includes
#include <QString>

//libgit2
#include "git2.h"

//std includes
#include <memory>
#include <optional>

namespace QQuickGit {

// RAII helper that opens a git repo, resolves a commit SHA, and extracts
// the commit tree and parent tree. Used by background diff/patch tasks
// that all need the same setup boilerplate.
struct CommitDiffContext
{
    using RepoPtr = std::unique_ptr<git_repository, decltype(&git_repository_free)>;
    using CommitPtr = std::unique_ptr<git_commit, decltype(&git_commit_free)>;
    using TreePtr = std::unique_ptr<git_tree, decltype(&git_tree_free)>;

    RepoPtr repo{nullptr, &git_repository_free};
    CommitPtr commit{nullptr, &git_commit_free};
    TreePtr commitTree{nullptr, &git_tree_free};
    TreePtr parentTree{nullptr, &git_tree_free};

    // Returns nullopt + sets errorMessage on failure.
    static std::optional<CommitDiffContext> open(const QString& repoPath,
                                                 const QString& commitSha,
                                                 int parentIndex,
                                                 QString& errorMessage)
    {
        CommitDiffContext ctx;

        git_repository* rawRepo = nullptr;
        if (git_repository_open(&rawRepo, repoPath.toLocal8Bit().constData()) != GIT_OK || !rawRepo) {
            errorMessage = QStringLiteral("Failed to open repository");
            return std::nullopt;
        }
        ctx.repo.reset(rawRepo);

        git_oid oid;
        if (git_oid_fromstr(&oid, commitSha.toLatin1().constData()) != GIT_OK) {
            errorMessage = QStringLiteral("Invalid commit SHA: %1").arg(commitSha);
            return std::nullopt;
        }

        git_commit* rawCommit = nullptr;
        if (git_commit_lookup(&rawCommit, ctx.repo.get(), &oid) != GIT_OK || !rawCommit) {
            errorMessage = QStringLiteral("Commit not found: %1").arg(commitSha);
            return std::nullopt;
        }
        ctx.commit.reset(rawCommit);

        git_tree* rawTree = nullptr;
        if (git_commit_tree(&rawTree, ctx.commit.get()) != GIT_OK || !rawTree) {
            errorMessage = QStringLiteral("Failed to get commit tree");
            return std::nullopt;
        }
        ctx.commitTree.reset(rawTree);

        unsigned int parentCount = git_commit_parentcount(ctx.commit.get());
        if (parentCount > 0) {
            int effective = qBound(0, parentIndex, static_cast<int>(parentCount) - 1);
            git_commit* rawParent = nullptr;
            if (git_commit_parent(&rawParent, ctx.commit.get(), effective) == GIT_OK && rawParent) {
                std::unique_ptr<git_commit, decltype(&git_commit_free)>
                    parentHolder(rawParent, &git_commit_free);
                git_tree* rawParentTree = nullptr;
                git_commit_tree(&rawParentTree, rawParent);
                ctx.parentTree.reset(rawParentTree);
            }
        }

        return ctx;
    }
};

} // namespace QQuickGit

#endif // COMMITDIFFCONTEXT_H
