//Catch includes
#include <catch2/catch_test_macros.hpp>

//Our includes
#include "GitGraphLaneItem.h"
#include "GitGraphModel.h"
#include "GitRepository.h"
#include "GitLaneType.h"

//Async includes
#include "asyncfuture.h"

//Qt includes
#include <QQuickWindow>
#include <QQuickItem>
#include <QSignalSpy>
#include <QDir>
#include <QTest>
#include <QTemporaryDir>
#include <QPainter>
#include <QFont>
#include <QFontMetrics>

using namespace QQuickGit;
using LT = GitLaneType::Type;
using RP = GitGraphLaneItem::RowPosition;

namespace {

struct LaneConfig {
    QString name;
    QList<int> lanes;
    int activeLane;
};

void renderConfig(const LaneConfig& config, const QString& outputPath,
                  const QList<QColor>& colors, int laneWidth, int rowHeight)
{
    const int itemWidth = qMax(laneWidth, config.lanes.size() * laneWidth);
    const int padding = 10;
    const int windowWidth = itemWidth + padding * 2;
    const int windowHeight = rowHeight * 3; // First + Middle + Last

    QQuickWindow window;
    window.setWidth(windowWidth);
    window.setHeight(windowHeight);
    window.setColor(Qt::white);

    // Create 3 rows: First, Middle, Last — shows how lines connect at row boundaries
    RP positions[] = { RP::First, RP::Middle, RP::Last };
    for (int r = 0; r < 3; ++r)
    {
        auto* item = new GitGraphLaneItem(window.contentItem());
        item->setX(padding);
        item->setY(r * rowHeight);
        item->setWidth(itemWidth);
        item->setHeight(rowHeight);
        item->setLanes(config.lanes);
        item->setActiveLane(config.activeLane);
        item->setColors(colors);
        item->setLaneWidth(laneWidth);
        item->setRowPosition(positions[r]);
    }

    window.show();
    REQUIRE(QTest::qWaitForWindowExposed(&window));

    QSignalSpy frameSpy(&window, &QQuickWindow::frameSwapped);
    window.update();
    REQUIRE(frameSpy.wait(5000));

    QImage img = window.grabWindow();
    REQUIRE(!img.isNull());
    REQUIRE(img.save(outputPath));
}

} // anonymous namespace

TEST_CASE("Render all lane types to PNG for visual inspection", "[visual]")
{
    const QList<QColor> colors = {
        QColor("#4dc9f6"), QColor("#f67019"), QColor("#f53794"),
        QColor("#537bc4"), QColor("#acc236")
    };
    const int laneWidth = 12;
    const int rowHeight = 32;

    // -- Single-lane types (activeLane = 0) --
    QList<LaneConfig> singleLane = {
        {"Empty",          {LT::Empty},          0},
        {"Active",         {LT::Active},         0},
        {"NotActive",      {LT::NotActive},      0},
        {"MergeFork",      {LT::MergeFork},      0},
        {"MergeForkRight", {LT::MergeForkRight}, 0},
        {"MergeForkLeft",  {LT::MergeForkLeft},  0},
        {"Join",           {LT::Join},           0},
        {"JoinRight",      {LT::JoinRight},      0},
        {"JoinLeft",       {LT::JoinLeft},       0},
        {"Head",           {LT::Head},           0},
        {"HeadRight",      {LT::HeadRight},      0},
        {"HeadLeft",       {LT::HeadLeft},       0},
        {"Tail",           {LT::Tail},           0},
        {"TailRight",      {LT::TailRight},      0},
        {"TailLeft",       {LT::TailLeft},       0},
        {"Cross",          {LT::Cross},          0},
        {"CrossEmpty",     {LT::CrossEmpty},     0},
        {"Initial",        {LT::Initial},        0},
        {"Branch",         {LT::Branch},         0},
    };

    // -- Multi-lane combinations --
    QList<LaneConfig> multiLane = {
        // Merge commit: lane 0 joins into active lane 1
        {"JoinLeft_HeadRight_a1",
            {LT::JoinLeft, LT::HeadRight}, 1},

        // Merge commit: lane 1 joins into active lane 0
        {"HeadLeft_JoinRight_a0",
            {LT::HeadLeft, LT::JoinRight}, 0},

        // Two parallel branches, left active
        {"Active_NotActive_a0",
            {LT::Active, LT::NotActive}, 0},

        // Two parallel branches, right active
        {"NotActive_Active_a1",
            {LT::NotActive, LT::Active}, 1},

        // Branch-off from active lane 0 to lane 1
        {"Active_Head_a0",
            {LT::Active, LT::Head}, 0},

        // Branch-off from active lane 1 to lane 0
        {"Head_Active_a1",
            {LT::Head, LT::Active}, 1},

        // Tail merging into active lane
        {"Active_Tail_a0",
            {LT::Active, LT::Tail}, 0},

        // Fork at root commit
        {"Initial_TailRight_a0",
            {LT::Initial, LT::TailRight}, 0},

        // MergeFork with pass-through
        {"MergeFork_NotActive_a0",
            {LT::MergeFork, LT::NotActive}, 0},

        // MergeFork right active
        {"NotActive_MergeFork_a1",
            {LT::NotActive, LT::MergeFork}, 1},

        // Cross pattern
        {"Active_Cross_NotActive_a0",
            {LT::Active, LT::Cross, LT::NotActive}, 0},

        // Three lanes, middle active with joins
        {"JoinLeft_MergeFork_JoinRight_a1",
            {LT::JoinLeft, LT::MergeFork, LT::JoinRight}, 1},

        // Branch starting new lane (discontinuity merge pattern)
        {"NotActive_Branch_a1",
            {LT::NotActive, LT::Branch}, 1},

        // Head type on active lane (discontinuity merge, post-fix)
        {"JoinLeft_Head_a1",
            {LT::JoinLeft, LT::Head}, 1},

        // HeadRight on active lane (PhakeCave3000 exact pattern)
        {"JoinLeft_HeadRight_a1_phakecave",
            {LT::JoinLeft, LT::HeadRight}, 1},

        // MergeForkLeft with TailRight (fork pattern)
        {"MergeForkLeft_TailRight_a0",
            {LT::MergeForkLeft, LT::TailRight}, 0},

        // MergeFork side lanes
        {"MergeForkLeft_NotActive_MergeForkRight_a0",
            {LT::MergeForkLeft, LT::NotActive, LT::MergeForkRight}, 0},
    };

    QString outputDir = QDir::currentPath() + "/lane_renders";
    QDir().mkpath(outputDir + "/single");
    QDir().mkpath(outputDir + "/multi");

    int index = 0;
    for (const auto& config : singleLane)
    {
        QString filename = QString("%1_%2.png")
            .arg(index, 2, 10, QChar('0'))
            .arg(config.name);
        QString path = outputDir + "/single/" + filename;
        renderConfig(config, path, colors, laneWidth, rowHeight);
        ++index;
    }

    index = 0;
    for (const auto& config : multiLane)
    {
        QString filename = QString("%1_%2.png")
            .arg(index, 2, 10, QChar('0'))
            .arg(config.name);
        QString path = outputDir + "/multi/" + filename;
        renderConfig(config, path, colors, laneWidth, rowHeight);
        ++index;
    }

    qDebug() << "Lane renders saved to:" << outputDir;
}

TEST_CASE("Render git-test-repository history to PNG", "[visual][clone]")
{
    // Clone the book/git-test-repository which has complex merge topologies
    QTemporaryDir tempDir;
    REQUIRE(tempDir.isValid());

    QDir clonePath(tempDir.path() + "/git-test-repository");

    GitRepository repo;
    repo.setDirectory(clonePath);

    auto cloneFuture = repo.clone(QUrl("https://github.com/book/git-test-repository.git"));
    REQUIRE(AsyncFuture::waitForFinished(cloneFuture, 30000));
    REQUIRE(!cloneFuture.result().hasError());

    // Load the graph model
    GitGraphModel model;
    model.setRepository(&repo);

    QSignalSpy loadingSpy(&model, &GitGraphModel::loadingChanged);
    if (model.loading())
        REQUIRE(loadingSpy.wait(10000));

    int rowCount = model.rowCount();
    REQUIRE(rowCount > 0);
    qDebug() << "git-test-repository has" << rowCount << "commits";

    // Render each row's lanes to a lane item, grab it, then composite
    // all rows + labels into a single tall PNG.
    const QList<QColor> colors = {
        QColor("#4dc9f6"), QColor("#f67019"), QColor("#f53794"),
        QColor("#537bc4"), QColor("#acc236"), QColor("#166a8f"),
        QColor("#00a950"), QColor("#8549ba")
    };
    const int laneWidth = 14;
    const int rowHeight = 56;

    // First pass: fetch lane data and determine max lane count for consistent width
    QVector<QList<int>> allLanes(rowCount);
    int maxLanes = 1;
    for (int i = 0; i < rowCount; ++i)
    {
        allLanes[i] = model.data(model.index(i), GitGraphModel::LanesRole).value<QList<int>>();
        maxLanes = qMax(maxLanes, allLanes[i].size());
    }

    // --- Helper lambdas for debug annotations ---

    // Short lane type abbreviation for compact display
    auto laneAbbrev = [](int type) -> QString {
        switch (type)
        {
        case LT::Empty:          return "E";
        case LT::Active:         return "Act";
        case LT::NotActive:      return "NA";
        case LT::MergeFork:      return "MF";
        case LT::MergeForkRight: return "MFR";
        case LT::MergeForkLeft:  return "MFL";
        case LT::Join:           return "J";
        case LT::JoinRight:      return "JR";
        case LT::JoinLeft:       return "JL";
        case LT::Head:           return "H";
        case LT::HeadRight:      return "HR";
        case LT::HeadLeft:       return "HL";
        case LT::Tail:           return "T";
        case LT::TailRight:      return "TR";
        case LT::TailLeft:       return "TL";
        case LT::Cross:          return "X";
        case LT::CrossEmpty:     return "XE";
        case LT::Initial:        return "Init";
        case LT::Branch:         return "Br";
        default:                 return "?";
        }
    };

    // Describe what the renderer draws for a given lane
    auto describeRendering = [](int type, int laneIdx, int activeLane, bool isFirst, bool isLast) -> QString {
        bool suppressTop = isFirst;
        bool suppressBottom = isLast;

        auto isHeadType = [](int t) { return t == LT::Head || t == LT::HeadLeft || t == LT::HeadRight; };
        auto isTailType = [](int t) { return t == LT::Tail || t == LT::TailLeft || t == LT::TailRight; };
        auto isJoinType = [](int t) { return t == LT::Join || t == LT::JoinLeft || t == LT::JoinRight; };
        auto isMergeForkSide = [](int t) { return t == LT::MergeForkLeft || t == LT::MergeForkRight; };

        auto hasTopLine = [](int t) {
            switch (t) {
            case LT::Active: case LT::NotActive: case LT::MergeFork:
            case LT::MergeForkLeft: case LT::MergeForkRight:
            case LT::Tail: case LT::TailLeft: case LT::TailRight:
            case LT::Join: case LT::JoinLeft: case LT::JoinRight:
            case LT::Cross: case LT::Initial:
                return true;
            default: return false;
            }
        };
        auto hasBottomLine = [](int t) {
            switch (t) {
            case LT::Active: case LT::NotActive: case LT::MergeFork:
            case LT::MergeForkLeft: case LT::MergeForkRight:
            case LT::Head: case LT::HeadLeft: case LT::HeadRight:
            case LT::Join: case LT::JoinLeft: case LT::JoinRight:
            case LT::Cross: case LT::Branch:
                return true;
            default: return false;
            }
        };

        if (type == LT::Empty || type == LT::CrossEmpty)
            return "skip";

        bool isCurved = (laneIdx != activeLane) &&
            (isHeadType(type) || isTailType(type) || isJoinType(type));

        QStringList ops;

        if (isCurved)
        {
            if (isHeadType(type))
            {
                if (!suppressBottom)
                    ops << "S-curve↓to-lane";
                else
                    ops << "suppress-bottom";
            }
            else // tail or join
            {
                if (!suppressTop)
                {
                    ops << "top-line";
                    ops << "curve→active";
                }
                else
                    ops << "suppress-top";

                if (isJoinType(type) && !suppressBottom)
                    ops << "bottom-line";
            }
        }
        else
        {
            if (hasTopLine(type) && !suppressTop)
                ops << "top";
            if (hasBottomLine(type) && !suppressBottom)
                ops << "bot";
            if (isMergeForkSide(type) && laneIdx != activeLane)
                ops << "horiz→active";
        }

        if (laneIdx == activeLane)
            ops << "●dot";

        return ops.isEmpty() ? "none" : ops.join("+");
    };

    const int laneAreaWidth = maxLanes * laneWidth;
    const int commitInfoWidth = 800;
    const int debugInfoWidth = 1200;
    const int totalWidth = laneAreaWidth + commitInfoWidth + debugInfoWidth + 80;

    // Key/legend at the top
    const int keyHeight = 280;
    const int totalHeight = keyHeight + rowCount * rowHeight;

    // Render each row's lane item individually and grab it
    QVector<QImage> laneImages;
    laneImages.reserve(rowCount);

    for (int i = 0; i < rowCount; ++i)
    {
        const auto& lanes = allLanes[i];
        int activeLane = model.data(model.index(i), GitGraphModel::ActiveLaneRole).toInt();

        RP position = RP::Middle;
        if (rowCount == 1)
            position = RP::Only;
        else if (i == 0)
            position = RP::First;
        else if (i == rowCount - 1)
            position = RP::Last;

        QQuickWindow window;
        window.setWidth(laneAreaWidth + 20);
        window.setHeight(rowHeight);
        window.setColor(Qt::white);

        auto* item = new GitGraphLaneItem(window.contentItem());
        item->setX(0);
        item->setY(0);
        item->setWidth(laneAreaWidth);
        item->setHeight(rowHeight);
        item->setLanes(lanes);
        item->setActiveLane(activeLane);
        item->setColors(colors);
        item->setLaneWidth(laneWidth);
        item->setRowPosition(position);

        window.show();
        REQUIRE(QTest::qWaitForWindowExposed(&window));

        QSignalSpy frameSpy(&window, &QQuickWindow::frameSwapped);
        window.update();
        REQUIRE(frameSpy.wait(5000));

        laneImages.append(window.grabWindow());
    }

    // Composite into a single image with labels + debug info
    QImage composite(totalWidth, totalHeight, QImage::Format_ARGB32);
    composite.fill(Qt::white);

    QPainter painter(&composite);
    QFont monoFont("monospace", 20);
    QFont smallMonoFont("monospace", 16);
    QFont labelFont("sans-serif", 22);
    QFont titleFont("sans-serif", 26);
    titleFont.setBold(true);
    painter.setRenderHint(QPainter::Antialiasing);

    // --- Draw key/legend ---
    {
        painter.setPen(Qt::NoPen);
        painter.setBrush(QColor(240, 240, 245));
        painter.drawRect(0, 0, totalWidth, keyHeight);

        int kx = 20;
        int ky = 36;

        painter.setFont(titleFont);
        painter.setPen(Qt::black);
        painter.drawText(kx, ky, "Abbreviation Key");

        painter.setFont(smallMonoFont);
        painter.setPen(QColor("#333333"));

        // Two-column layout for abbreviations
        struct KeyEntry { const char* abbrev; const char* full; };
        KeyEntry entries[] = {
            {"Act",  "Active"},
            {"NA",   "NotActive"},
            {"MF",   "MergeFork"},
            {"MFL",  "MergeForkLeft"},
            {"MFR",  "MergeForkRight"},
            {"J",    "Join"},
            {"JL",   "JoinLeft"},
            {"JR",   "JoinRight"},
            {"H",    "Head"},
            {"HL",   "HeadLeft"},
            {"HR",   "HeadRight"},
            {"T",    "Tail"},
            {"TL",   "TailLeft"},
            {"TR",   "TailRight"},
            {"X",    "Cross"},
            {"XE",   "CrossEmpty"},
            {"Init", "Initial"},
            {"Br",   "Branch"},
            {"E",    "Empty"},
        };

        const int numEntries = sizeof(entries) / sizeof(entries[0]);
        const int colWidth = 320;
        const int lineHeight = 24;
        const int entriesPerCol = 7;

        for (int e = 0; e < numEntries; ++e)
        {
            int col = e / entriesPerCol;
            int row = e % entriesPerCol;
            int ex = kx + col * colWidth;
            int ey = ky + 16 + row * lineHeight;

            painter.setPen(QColor("#0066cc"));
            painter.drawText(ex, ey, QString::fromLatin1(entries[e].abbrev));
            painter.setPen(QColor("#333333"));
            painter.drawText(ex + 70, ey, QString("= %1").arg(entries[e].full));
        }

        // Symbols key on the right
        int sx = kx + 3 * colWidth + 40;
        int sy = ky + 32;

        painter.setPen(Qt::black);
        painter.setFont(smallMonoFont);
        painter.drawText(sx, sy,      "*  = active lane");
        painter.drawText(sx, sy + lineHeight, QString::fromUtf8("●dot = commit node drawn"));
        painter.drawText(sx, sy + lineHeight * 2, "top = line from top to midY");
        painter.drawText(sx, sy + lineHeight * 3, "bot = line from midY to bottom");
        painter.drawText(sx, sy + lineHeight * 4, QString::fromUtf8("S-curve↓ = bezier curve down to lane"));
        painter.drawText(sx, sy + lineHeight * 5, QString::fromUtf8("curve→active = curve from lane to dot"));
        painter.drawText(sx, sy + lineHeight * 6, QString::fromUtf8("horiz→active = horizontal line to dot"));

        // Separator line
        painter.setPen(QColor("#cccccc"));
        painter.drawLine(0, keyHeight - 1, totalWidth, keyHeight - 1);
    }

    // --- Draw commit rows ---
    for (int i = 0; i < rowCount; ++i)
    {
        int y = keyHeight + i * rowHeight;
        bool isFirst = (i == 0);
        bool isLast = (i == rowCount - 1);

        // Alternate row background for readability
        if (i % 2 == 1)
        {
            painter.setPen(Qt::NoPen);
            painter.setBrush(QColor(245, 245, 250));
            painter.drawRect(0, y, totalWidth, rowHeight);
        }

        // Draw lane image
        if (!laneImages[i].isNull())
            painter.drawImage(0, y, laneImages[i]);

        // --- Commit info column ---
        QModelIndex idx = model.index(i);
        QString sha = model.data(idx, GitGraphModel::ShaRole).toString().left(7);
        QString message = model.data(idx, GitGraphModel::MessageRole).toString();
        auto refs = model.data(idx, GitGraphModel::RefsRole).toStringList();
        const auto& lanes = allLanes[i];
        int activeLane = model.data(idx, GitGraphModel::ActiveLaneRole).toInt();
        bool isHead = model.data(idx, GitGraphModel::IsHeadRole).toBool();

        int textX = laneAreaWidth + 20;
        int textY = y + rowHeight / 2;

        // SHA
        painter.setFont(monoFont);
        painter.setPen(QColor("#888888"));
        painter.drawText(textX, textY + 8, sha);
        textX += 130;

        // Refs
        painter.setFont(labelFont);
        for (const auto& ref : refs)
        {
            QColor refColor = colors[activeLane % colors.size()];
            painter.setPen(Qt::NoPen);
            painter.setBrush(refColor.lighter(170));

            QFontMetrics fm(labelFont);
            int refWidth = fm.horizontalAdvance(ref) + 16;
            painter.drawRoundedRect(textX, y + 8, refWidth, rowHeight - 16, 6, 6);

            painter.setPen(refColor.darker(120));
            painter.drawText(textX + 8, textY + 8, ref);
            textX += refWidth + 8;
        }

        // Message
        painter.setPen(isHead ? Qt::black : QColor("#333333"));
        if (isHead)
        {
            QFont boldFont = labelFont;
            boldFont.setBold(true);
            painter.setFont(boldFont);
        }
        else
            painter.setFont(labelFont);
        painter.drawText(textX, textY + 8, message);

        // --- Debug info column ---
        int debugX = laneAreaWidth + commitInfoWidth + 40;

        // Lane types: "a=1 [0:JL 1:MF* 2:T 3:XE 4:TR]"
        QStringList laneLabels;
        for (int l = 0; l < lanes.size(); ++l)
        {
            QString label = QString("%1:%2").arg(l).arg(laneAbbrev(lanes[l]));
            if (l == activeLane)
                label += "*";
            laneLabels << label;
        }

        painter.setFont(smallMonoFont);
        painter.setPen(QColor("#555555"));
        QString laneStr = QString("a=%1 [%2]").arg(activeLane).arg(laneLabels.join(" "));
        painter.drawText(debugX, textY, laneStr);

        // Rendering decisions for each lane: "0:top+bot+●dot 1:S-curve↓"
        QStringList renderOps;
        for (int l = 0; l < lanes.size(); ++l)
        {
            QString desc = describeRendering(lanes[l], l, activeLane, isFirst, isLast);
            renderOps << QString("%1:%2").arg(l).arg(desc);
        }

        painter.setPen(QColor("#999999"));
        painter.drawText(debugX, textY + 20, renderOps.join("  "));
    }

    painter.end();

    // Save
    QString outputDir = QDir::currentPath() + "/lane_renders";
    QDir().mkpath(outputDir);
    QString outputPath = outputDir + "/git_test_repository.png";
    REQUIRE(composite.save(outputPath));
    qDebug() << "git-test-repository render saved to:" << outputPath;
}
