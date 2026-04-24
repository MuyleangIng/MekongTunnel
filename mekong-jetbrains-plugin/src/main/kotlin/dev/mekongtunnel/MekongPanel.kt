package dev.mekongtunnel

import com.intellij.ide.BrowserUtil
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.project.Project
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBScrollPane
import com.intellij.util.ui.JBUI
import java.awt.*
import java.awt.datatransfer.StringSelection
import java.awt.geom.RoundRectangle2D
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.*
import javax.swing.border.EmptyBorder
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants

// ── Palette — JBColor(light, dark) adapts to IntelliJ theme ───────────────────
private val C_PAGE        = JBColor(Color(0xf5, 0xf5, 0xf7), Color(0x0d, 0x11, 0x17))
private val C_SHELL       = JBColor(Color(0xeb, 0xec, 0xf0), Color(0x16, 0x1b, 0x22))
private val C_CARD        = JBColor(Color(0xe2, 0xe4, 0xea), Color(0x1c, 0x22, 0x2b))
private val C_INPUT       = JBColor(Color(0xff, 0xff, 0xff), Color(0x13, 0x18, 0x20))
private val C_BORDER      = JBColor(Color(0xc8, 0xca, 0xd4), Color(0x2d, 0x35, 0x42))
private val C_ACCENT      = JBColor(Color(0x0e, 0x63, 0x9c), Color(0x37, 0x94, 0xff))
private val C_STRONG      = JBColor(Color(0x0a, 0x4f, 0x7a), Color(0x0e, 0x63, 0x9c))
private val C_GREEN       = JBColor(Color(0x18, 0x9e, 0x48), Color(0x22, 0xc5, 0x5e))
private val C_FG          = JBColor(Color(0x1a, 0x1a, 0x1a), Color(0xf0, 0xf2, 0xf5))
private val C_FGMUT       = JBColor(Color(0x55, 0x5f, 0x70), Color(0x8b, 0x96, 0xab))
private val C_SUCC_T      = JBColor(Color(0x18, 0x7a, 0x38), Color(0x86, 0xef, 0xac))
private val C_ERR_T       = JBColor(Color(0xb9, 0x1c, 0x1c), Color(0xfc, 0xa5, 0xa5))
private val C_WARN_T      = JBColor(Color(0x1d, 0x4e, 0x89), Color(0xc6, 0xe2, 0xff))
private val C_URL         = JBColor(Color(0x02, 0x69, 0xa4), Color(0x7d, 0xd3, 0xfc))
// secondary / utility
private val C_BTN_SEC     = JBColor(Color(0xd4, 0xd6, 0xde), Color(0x22, 0x28, 0x35))
private val C_BTN_DNGR    = JBColor(Color(0xfe, 0xe2, 0xe2), Color(0x2a, 0x10, 0x10))
private val C_BTN_DNGR_BD = JBColor(Color(0xf8, 0x71, 0x71), Color(0x6b, 0x21, 0x21))
private val C_LIVE_BTN    = JBColor(Color(0x16, 0x7a, 0x3a), Color(0x14, 0x60, 0x34))
private val C_ACCT_CARD   = JBColor(Color(0xd8, 0xfb, 0xe8), Color(0x1a, 0x1e, 0x28))
private val C_AVATAR      = JBColor(Color(0xc8, 0xcc, 0xd8), Color(0x2a, 0x32, 0x42))
private val C_PILL_BG     = JBColor(Color(0xdc, 0xfc, 0xe8), Color(0x0c, 0x26, 0x18))
private val C_PILL_BD     = JBColor(Color(0x86, 0xef, 0xac), Color(0x22, 0x55, 0x33))
private val C_OFF_BADGE   = JBColor(Color(0xd4, 0xd6, 0xde), Color(0x22, 0x28, 0x35))
private val C_DOT_IDLE    = JBColor(Color(0xb0, 0xb8, 0xc8), Color(0x3e, 0x46, 0x56))
private val C_LOG_BG      = JBColor(Color(0xf4, 0xf5, 0xf7), Color(0x08, 0x0c, 0x12))
private val C_LOG_FG      = JBColor(Color(0x1a, 0x1a, 0x1a), Color(0xc0, 0xc8, 0xd4))
private val C_LOG_TS      = JBColor(Color(0x7a, 0x8a, 0xa0), Color(0x3e, 0x50, 0x6a))
private val C_LOG_EMPTY   = JBColor(Color(0x7a, 0x8a, 0xa0), Color(0x55, 0x60, 0x72))

// ── RoundButton — fully custom-rendered, truly rounded ────────────────────────
private open class RoundButton(
    text: String,
    private val bg: Color,
    private val fg: Color,
    private val radius: Int = 10,
    private val borderCol: Color? = null,
) : JButton(text) {
    init {
        isOpaque = false; isContentAreaFilled = false; isBorderPainted = false; isFocusPainted = false
        foreground = fg; cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        font = font.deriveFont(Font.BOLD, 12f)
    }
    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        val paintBg = if (model.isPressed) bg.darker() else if (model.isRollover) brighten(bg) else bg
        g2.color = paintBg
        g2.fill(RoundRectangle2D.Float(0f, 0f, width.toFloat(), height.toFloat(), radius * 2f, radius * 2f))
        if (borderCol != null) {
            g2.color = borderCol; g2.stroke = BasicStroke(1f)
            g2.draw(RoundRectangle2D.Float(.5f, .5f, width - 1f, height - 1f, radius * 2f, radius * 2f))
        }
        g2.dispose()
        super.paintComponent(g)
    }
    private fun brighten(c: Color) = Color(
        (c.red   + 20).coerceAtMost(255),
        (c.green + 20).coerceAtMost(255),
        (c.blue  + 20).coerceAtMost(255),
    )
}

// ── CardPanel — rounded filled background ─────────────────────────────────────
private open class CardPanel(
    private val radius: Int = 12,
    private val fill: Color = C_CARD,
    private val stroke: Color? = C_BORDER,
) : JPanel() {
    init { isOpaque = false }
    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.color = fill
        g2.fill(RoundRectangle2D.Float(0f, 0f, width.toFloat(), height.toFloat(), radius * 2f, radius * 2f))
        if (stroke != null) {
            g2.color = stroke; g2.stroke = BasicStroke(1f)
            g2.draw(RoundRectangle2D.Float(.5f, .5f, width - 1f, height - 1f, radius * 2f, radius * 2f))
        }
        g2.dispose()
        super.paintComponent(g)
    }
}

// ── DotIndicator ──────────────────────────────────────────────────────────────
private class DotIndicator(var col: Color = C_DOT_IDLE) : JPanel() {
    init { isOpaque = false; preferredSize = Dimension(9, 9); minimumSize = Dimension(9, 9); maximumSize = Dimension(9, 9) }
    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.color = col; g2.fillOval(0, 0, 9, 9); g2.dispose()
    }
}

// ── TabButton — VS Code bottom-accent style ───────────────────────────────────
private class TabButton(private val label: String, var active: Boolean = false) : JButton(label) {
    init { isOpaque = false; isContentAreaFilled = false; isBorderPainted = false; isFocusPainted = false; cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR) }
    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.color = if (active) C_SHELL else C_CARD; g2.fillRect(0, 0, width, height)
        g2.font = font.deriveFont(if (active) Font.BOLD else Font.PLAIN, 12f)
        g2.color = if (active) C_FG else C_FGMUT
        val fm = g2.fontMetrics; val tx = (width - fm.stringWidth(label)) / 2; val ty = (height + fm.ascent - fm.descent) / 2
        g2.drawString(label, tx, ty)
        if (active) { g2.color = C_ACCENT; g2.fillRect(0, height - 2, width, 2) }
        g2.dispose()
    }
}

// ── GridBag helper — fills full width, no alignment chaos ────────────────────
private fun gbc(row: Int, padTop: Int = 0, padLR: Int = 0): GridBagConstraints = GridBagConstraints().apply {
    fill = GridBagConstraints.HORIZONTAL; weightx = 1.0
    gridwidth = GridBagConstraints.REMAINDER; gridx = 0; gridy = row
    insets = Insets(padTop, padLR, 0, padLR)
}

// ── Simple layout helpers ──────────────────────────────────────────────────────
private fun transparent(layout: LayoutManager? = null): JPanel =
    JPanel(layout ?: FlowLayout()).apply { isOpaque = false }

private fun lbl(text: String, fg: Color, sz: Float, bold: Boolean = false): JLabel =
    JLabel(text).apply { foreground = fg; font = font.deriveFont(if (bold) Font.BOLD else Font.PLAIN, sz) }

private fun sectionLbl(text: String): JLabel = lbl(text.uppercase(), C_FGMUT, 10f, bold = true)
    .apply { border = EmptyBorder(0, 0, 7, 0) }

private fun hsep(): JPanel = JPanel().apply {
    background = C_BORDER; isOpaque = true
    preferredSize = Dimension(1, 1); minimumSize = Dimension(0, 1); maximumSize = Dimension(Int.MAX_VALUE, 1)
}

private fun styleInput(f: JTextField) {
    f.background = C_INPUT; f.foreground = C_FG; f.caretColor = C_FG; f.isOpaque = true
    f.border = BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(C_BORDER, 1), EmptyBorder(0, 10, 0, 10))
    f.font = f.font.deriveFont(12f); f.preferredSize = Dimension(9999, 36); f.maximumSize = Dimension(Int.MAX_VALUE, 36)
}

private fun styleCombo(c: JComboBox<*>) {
    c.background = C_INPUT; c.foreground = C_FG; c.isOpaque = true
    c.border = BorderFactory.createLineBorder(C_BORDER, 1); c.font = c.font.deriveFont(12f)
    c.preferredSize = Dimension(9999, 36); c.maximumSize = Dimension(Int.MAX_VALUE, 36)
}

// ── Button factory functions ──────────────────────────────────────────────────
private fun primaryBtn(text: String, bg: Color = C_STRONG): RoundButton =
    RoundButton(text, bg, Color.WHITE, radius = 12).apply {
        preferredSize = Dimension(9999, 40); maximumSize = Dimension(Int.MAX_VALUE, 40)
    }

private fun dangerBtn(text: String): RoundButton =
    RoundButton(text, C_BTN_DNGR, C_ERR_T, radius = 12, borderCol = C_BTN_DNGR_BD).apply {
        preferredSize = Dimension(9999, 38); maximumSize = Dimension(Int.MAX_VALUE, 38)
    }

private fun ghostBtn(text: String, h: Int = 34): RoundButton =
    RoundButton(text, C_BTN_SEC, C_FG, radius = 10, borderCol = C_BORDER).apply {
        font = font.deriveFont(Font.PLAIN, 12f)
        preferredSize = Dimension(9999, h); maximumSize = Dimension(Int.MAX_VALUE, h)
    }

private fun halfGhostBtn(text: String): RoundButton =
    RoundButton(text, C_BTN_SEC, C_FG, radius = 10, borderCol = C_BORDER).apply {
        font = font.deriveFont(Font.PLAIN, 12f); preferredSize = Dimension(9999, 34)
    }

private fun miniBtn(text: String): RoundButton =
    RoundButton(text, C_BTN_SEC, C_FG, radius = 8, borderCol = C_BORDER).apply {
        font = font.deriveFont(Font.PLAIN, 11f); preferredSize = Dimension(72, 28); maximumSize = Dimension(72, 28)
    }

// ── Section card ──────────────────────────────────────────────────────────────
private fun sectionCard(
    fill: Color = C_CARD, stroke: Color = C_BORDER,
    top: Int = 12, lr: Int = 12, bottom: Int = 12,
): CardPanel = CardPanel(12, fill, stroke).apply {
    layout = GridBagLayout(); border = EmptyBorder(top, lr, bottom, lr)
}

private fun CardPanel.addFull(comp: Component, row: Int, padTop: Int = 0) {
    add(comp, gbc(row, padTop))
}

// ══════════════════════════════════════════════════════════════════════════════
class MekongPanel(private val project: Project? = null) : JPanel(BorderLayout()) {

    private val svc = MekongService.getInstance()
    private val df  = SimpleDateFormat("HH:mm:ss")

    // ── Tunnel widgets ────────────────────────────────────────────────────────
    private val portField    = JTextField("3000")
    private val expireCombo  = JComboBox(arrayOf(
        "No expiry (session only)", "30 minutes", "1 hour", "6 hours",
        "12 hours", "24 hours (1 day)", "2 days", "7 days (1 week)", "2 weeks", "1 month"
    ))
    private val expireValues = arrayOf("", "30m", "1h", "6h", "12h", "24h", "2d", "7d", "2w", "1mo")
    private val startBtn     = primaryBtn("Start Tunnel")
    private val stopBtn      = dangerBtn("Stop Tunnel")
    private val copyBtn      = halfGhostBtn("Copy")
    private val openBtn      = halfGhostBtn("Open")
    private val urlLabel     = lbl("—", C_URL, 11f)

    // ── Live Server widgets ───────────────────────────────────────────────────
    private val liveStartBtn  = primaryBtn("Open with Live Server", C_LIVE_BTN)
    private val livePreviewBtn = ghostBtn("Open with Mekong Preview", 36)
    private val liveStopBtn   = dangerBtn("Stop Live Server")
    private val liveCopyBtn   = halfGhostBtn("Copy")
    private val liveOpenBtn   = halfGhostBtn("Open")
    private val liveUrlLabel  = lbl("—", C_ACCENT, 11f)

    // ── Status / Account ──────────────────────────────────────────────────────
    private val mainDot   = DotIndicator()
    private val mainLabel = lbl("No active tunnel", C_FG, 13f, bold = true)
    private val mainSub   = lbl("Ready to connect", C_FGMUT, 11f)
    private val loginBtn  = miniBtn("Log in")
    private val logoutBtn = miniBtn("Log out").apply { foreground = C_ERR_T }

    private val acctCard = CardPanel(12, C_ACCT_CARD, C_BORDER)
    private val acctName = lbl("Not logged in", C_FG, 12f, bold = true)
    private val acctSub  = lbl("Login for a reserved subdomain", C_FGMUT, 11f)

    // ── Tabs ──────────────────────────────────────────────────────────────────
    private val tabTunnel = TabButton("Tunnel", active = true)
    private val tabLive   = TabButton("Live Server", active = false)
    private val screens   = JPanel(CardLayout()).apply { isOpaque = false }

    // ── Dynamic sections (show/hide) ──────────────────────────────────────────
    private lateinit var tunnelIdleSection:   JPanel
    private lateinit var tunnelActiveSection: JPanel
    private lateinit var lsIdleSection:       JPanel
    private lateinit var lsActiveSection:     JPanel

    // ── Log — terminal-style JTextPane ───────────────────────────────────────
    private val logPane = JTextPane().apply {
        isEditable = false; isOpaque = true
        background = C_LOG_BG; foreground = C_LOG_FG
        font = Font(Font.MONOSPACED, Font.PLAIN, 11)
        border = EmptyBorder(8, 12, 8, 12)
    }
    private val logDoc = logPane.styledDocument

    // ── Init ──────────────────────────────────────────────────────────────────
    init {
        background = C_PAGE; isOpaque = true; border = EmptyBorder(JBUI.insets(8))
        styleInput(portField); styleCombo(expireCombo)
        urlLabel.font = Font(Font.MONOSPACED, Font.PLAIN, 11)
        liveUrlLabel.font = Font(Font.MONOSPACED, Font.PLAIN, 11)

        screens.add(buildTunnelScreen(), "tunnel")
        screens.add(buildLiveScreen(),   "live")

        // NORTH inside BorderLayout forces the shell to fill full viewport width
        val wrapper = JPanel(BorderLayout()).apply { background = C_PAGE; isOpaque = true }
        wrapper.add(buildShell(), BorderLayout.NORTH)

        val scroll = JBScrollPane(wrapper).apply {
            border = null; background = C_PAGE; viewport.background = C_PAGE
            horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER
            verticalScrollBar.unitIncrement = 16
        }
        add(scroll, BorderLayout.CENTER)

        tabTunnel.addActionListener { switchTab("tunnel") }
        tabLive.addActionListener   { switchTab("live") }

        wireActions()
        svc.addListener { SwingUtilities.invokeLater { render() } }
        render()
    }

    // ── Shell — GridBagLayout guarantees every row fills full width ────────────

    private fun buildShell(): JPanel {
        val shell = CardPanel(14, C_SHELL, C_BORDER)
        shell.layout = GridBagLayout()
        var r = 0
        fun row(comp: Component, top: Int = 0) = shell.add(comp, gbc(r++, top))

        row(buildHeader())
        row(hsep())
        row(buildStatusBar())
        row(hsep())
        row(buildAccountSection(),  top = 10)
        row(buildTabBar())
        row(screens)
        row(buildActivityLog())
        return shell
    }

    // ── Header ────────────────────────────────────────────────────────────────

    private fun buildHeader(): JPanel {
        val p = JPanel(BorderLayout(10, 0)).apply {
            isOpaque = false; border = EmptyBorder(12, 14, 12, 14)
        }
        val logoUrl = MekongPanel::class.java.getResource("/icons/MekongNoBG.png")
        val logo = if (logoUrl != null)
            JLabel(ImageIcon(ImageIcon(logoUrl).image.getScaledInstance(34, 34, Image.SCALE_SMOOTH)))
        else
            JLabel("M").apply { foreground = C_ACCENT; font = font.deriveFont(Font.BOLD, 16f); horizontalAlignment = SwingConstants.CENTER }
        logo.preferredSize = Dimension(34, 34)

        val brandPanel = JPanel(GridLayout(2, 1, 0, 2)).apply { isOpaque = false }
        brandPanel.add(lbl("Mekong Tunnel", C_FG, 15f, bold = true))
        brandPanel.add(lbl("mekongtunnel.dev", C_FGMUT, 11f))

        p.add(logo,       BorderLayout.WEST)
        p.add(brandPanel, BorderLayout.CENTER)
        return p
    }

    // ── Status bar ────────────────────────────────────────────────────────────

    private fun buildStatusBar(): JPanel {
        val p = JPanel(BorderLayout(10, 0)).apply {
            isOpaque = false; border = EmptyBorder(10, 14, 10, 14)
        }
        val leftInfo = JPanel(GridLayout(2, 1, 0, 3)).apply { isOpaque = false }
        val dotRow = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply { isOpaque = false; add(mainDot); add(Box.createHorizontalStrut(8)); add(mainLabel) }
        leftInfo.add(dotRow); leftInfo.add(mainSub)

        val btnRow = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply { isOpaque = false; add(loginBtn); add(logoutBtn) }
        p.add(leftInfo, BorderLayout.CENTER)
        p.add(btnRow,   BorderLayout.EAST)
        return p
    }

    // ── Account card ──────────────────────────────────────────────────────────

    private fun buildAccountSection(): JPanel {
        val avatar = object : CardPanel(8, C_AVATAR, C_BORDER) {
            init { layout = BorderLayout(); preferredSize = Dimension(32, 32); minimumSize = Dimension(32, 32); maximumSize = Dimension(32, 32) }
        }
        avatar.add(JLabel("MK", SwingConstants.CENTER).apply { foreground = C_FG; font = font.deriveFont(Font.BOLD, 11f) }, BorderLayout.CENTER)

        val infoGrid = JPanel(GridLayout(2, 1, 0, 2)).apply { isOpaque = false; add(acctName); add(acctSub) }
        val inner    = JPanel(BorderLayout(10, 0)).apply { isOpaque = false; add(avatar, BorderLayout.WEST); add(infoGrid, BorderLayout.CENTER) }

        acctCard.apply {
            layout = BorderLayout(); border = EmptyBorder(11, 12, 11, 12)
            add(inner, BorderLayout.CENTER)
        }
        val wrap = JPanel(GridBagLayout()).apply { isOpaque = false }
        wrap.add(acctCard, gbc(0, 0, 10))
        return wrap
    }

    // ── Tab bar ───────────────────────────────────────────────────────────────

    private fun buildTabBar(): JPanel {
        val tabRow = JPanel(GridLayout(1, 2)).apply {
            isOpaque = true; background = C_CARD
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(6, 10, 0, 10),
                BorderFactory.createLineBorder(C_BORDER, 1)
            )
        }
        tabTunnel.preferredSize = Dimension(9999, 38)
        tabLive.preferredSize   = Dimension(9999, 38)
        tabRow.add(tabTunnel); tabRow.add(tabLive)

        val wrap = JPanel(GridBagLayout()).apply { isOpaque = false }
        wrap.add(tabRow, gbc(0, 0, 0))
        return wrap
    }

    // ── Tunnel screen ─────────────────────────────────────────────────────────

    private fun buildTunnelScreen(): JPanel {
        val screen = JPanel(GridBagLayout()).apply { isOpaque = false; border = EmptyBorder(6, 10, 10, 10) }
        var r = 0

        // Port + Detect row
        val detectBtn = RoundButton("Detect", C_BTN_SEC, C_FG, 8, C_BORDER).apply {
            font = font.deriveFont(Font.PLAIN, 12f); preferredSize = Dimension(76, 36); maximumSize = Dimension(76, 36)
        }
        val portRow = JPanel(BorderLayout(8, 0)).apply {
            isOpaque = false; add(portField, BorderLayout.CENTER); add(detectBtn, BorderLayout.EAST)
        }
        val frameworkNote = lbl("", C_FGMUT, 11f)
        detectBtn.addActionListener { frameworkNote.text = "Port set to ${portField.text}" }

        val portCard = sectionCard()
        portCard.addFull(sectionLbl("Local Port"), 0)
        portCard.addFull(portRow,                  1)
        portCard.addFull(frameworkNote,            2, 5)

        // Expiry
        val expCard = sectionCard()
        expCard.addFull(sectionLbl("Expiry"),  0)
        expCard.addFull(expireCombo,           1)

        // Info card
        val infoCard = sectionCard(top = 11, bottom = 11)
        infoCard.addFull(lbl("Public URL", C_FG, 12f, bold = true), 0)
        infoCard.addFull(lbl("A public URL is generated when the tunnel starts.", C_FGMUT, 11f), 1, 4)

        // Start section
        val startSec = sectionCard(top = 8, bottom = 8)
        startSec.addFull(startBtn, 0)

        tunnelIdleSection = JPanel(GridBagLayout()).apply { isOpaque = false }
        var ir = 0
        tunnelIdleSection.add(portCard,  gbc(ir++))
        tunnelIdleSection.add(expCard,   gbc(ir++, 8))
        tunnelIdleSection.add(infoCard,  gbc(ir++, 8))
        tunnelIdleSection.add(startSec,  gbc(ir++, 8))

        // Active URL section
        val activePill = sectionCard(C_PILL_BG, C_PILL_BD, top = 11, bottom = 11)
        activePill.layout = BorderLayout(9, 0)
        activePill.border = EmptyBorder(11, 12, 11, 12)
        val gd = DotIndicator(C_GREEN)
        val gdWrap = JPanel(BorderLayout()).apply { isOpaque = false; border = EmptyBorder(3, 0, 0, 0); add(gd, BorderLayout.NORTH) }
        val pillInfo = JPanel(GridLayout(2, 1, 0, 2)).apply {
            isOpaque = false
            add(lbl("Tunnel active", C_SUCC_T, 12f, bold = true))
            add(lbl("Traffic is forwarded to your local app.", C_FGMUT, 11f))
        }
        activePill.add(gdWrap,    BorderLayout.WEST)
        activePill.add(pillInfo,  BorderLayout.CENTER)

        urlLabel.font = Font(Font.MONOSPACED, Font.PLAIN, 11)
        val actRow = JPanel(GridLayout(1, 2, 8, 0)).apply { isOpaque = false; add(copyBtn); add(openBtn) }
        val pubCard = sectionCard()
        pubCard.addFull(lbl("PUBLIC URL", C_FGMUT, 10f, bold = true), 0)
        pubCard.addFull(urlLabel,                                      1, 5)
        pubCard.addFull(actRow,                                        2, 8)

        val stopSec = sectionCard(top = 8, bottom = 8)
        stopSec.addFull(stopBtn, 0)

        tunnelActiveSection = JPanel(GridBagLayout()).apply { isOpaque = false; isVisible = false }
        var ar = 0
        tunnelActiveSection.add(activePill, gbc(ar++))
        tunnelActiveSection.add(pubCard,    gbc(ar++, 8))
        tunnelActiveSection.add(stopSec,    gbc(ar++, 8))

        val viewLogBtn = ghostBtn("View output log", 34)

        screen.add(tunnelIdleSection,   gbc(r++))
        screen.add(tunnelActiveSection, gbc(r++))
        screen.add(viewLogBtn,          gbc(r++, 8))
        return screen
    }

    // ── Live Server screen ────────────────────────────────────────────────────

    private fun buildLiveScreen(): JPanel {
        val screen = JPanel(GridBagLayout()).apply { isOpaque = false; border = EmptyBorder(6, 10, 10, 10) }
        var r = 0

        // Status card
        val lsDot  = DotIndicator()
        val offBadge = object : CardPanel(999, C_OFF_BADGE, C_BORDER) {
            init { layout = FlowLayout(FlowLayout.CENTER, 8, 3); preferredSize = Dimension(38, 22); maximumSize = Dimension(38, 22) }
        }
        offBadge.add(lbl("Off", C_FGMUT, 10f, bold = true))
        val dotWrap   = JPanel(BorderLayout()).apply { isOpaque = false; border = EmptyBorder(3, 0, 0, 0); add(lsDot, BorderLayout.NORTH) }
        val lsInfo    = JPanel(GridLayout(2, 1, 0, 2)).apply {
            isOpaque = false
            add(lbl("Not running", C_FG, 13f, bold = true))
            add(lbl("Start to serve HTML or Markdown with live reload.", C_FGMUT, 11f))
        }
        val statusInner = JPanel(BorderLayout(10, 0)).apply { isOpaque = false; add(dotWrap, BorderLayout.WEST); add(lsInfo, BorderLayout.CENTER); add(offBadge, BorderLayout.EAST) }
        val statusCard = sectionCard(top = 12, bottom = 12)
        statusCard.layout = BorderLayout(); statusCard.border = EmptyBorder(12, 12, 12, 12)
        statusCard.add(statusInner, BorderLayout.CENTER)

        // Info card
        val infoCard = sectionCard(top = 11, bottom = 11)
        infoCard.addFull(lbl("Preview modes", C_FG, 12f, bold = true), 0)
        infoCard.addFull(lbl("Open HTML or Markdown in browser with live reload.", C_FGMUT, 11f), 1, 4)

        val lsStartSec = sectionCard(top = 8, bottom = 8)
        lsStartSec.addFull(liveStartBtn,   0)
        lsStartSec.addFull(livePreviewBtn, 1, 8)

        lsIdleSection = JPanel(GridBagLayout()).apply { isOpaque = false }
        var ir = 0
        lsIdleSection.add(statusCard,  gbc(ir++))
        lsIdleSection.add(infoCard,    gbc(ir++, 8))
        lsIdleSection.add(lsStartSec,  gbc(ir++, 8))

        // Active section
        val lsPill = sectionCard(C_PILL_BG, C_PILL_BD, top = 11, bottom = 11)
        lsPill.layout = BorderLayout(9, 0); lsPill.border = EmptyBorder(11, 12, 11, 12)
        val lgd  = DotIndicator(C_GREEN)
        val lgdW = JPanel(BorderLayout()).apply { isOpaque = false; border = EmptyBorder(3,0,0,0); add(lgd, BorderLayout.NORTH) }
        val lsPillInfo = JPanel(GridLayout(2, 1, 0, 2)).apply {
            isOpaque = false
            add(lbl("Live reload active", C_SUCC_T, 12f, bold = true))
            add(lbl("Changes will refresh automatically.", C_FGMUT, 11f))
        }
        lsPill.add(lgdW, BorderLayout.WEST); lsPill.add(lsPillInfo, BorderLayout.CENTER)

        liveUrlLabel.font = Font(Font.MONOSPACED, Font.PLAIN, 11)
        val lsActRow = JPanel(GridLayout(1, 2, 8, 0)).apply { isOpaque = false; add(liveCopyBtn); add(liveOpenBtn) }
        val lsUrlCard = sectionCard()
        lsUrlCard.addFull(lbl("LOCAL URL", C_FGMUT, 10f, bold = true), 0)
        lsUrlCard.addFull(liveUrlLabel,                                 1, 5)
        lsUrlCard.addFull(lsActRow,                                     2, 8)

        val lsStopSec = sectionCard(top = 8, bottom = 8)
        lsStopSec.addFull(liveStopBtn, 0)

        lsActiveSection = JPanel(GridBagLayout()).apply { isOpaque = false; isVisible = false }
        var ar = 0
        lsActiveSection.add(lsPill,    gbc(ar++))
        lsActiveSection.add(lsUrlCard, gbc(ar++, 8))
        lsActiveSection.add(lsStopSec, gbc(ar++, 8))

        val viewLogBtn = ghostBtn("View output log", 34)

        screen.add(lsIdleSection,   gbc(r++))
        screen.add(lsActiveSection, gbc(r++))
        screen.add(viewLogBtn,      gbc(r++, 8))
        return screen
    }

    // ── Activity Log — terminal-style ─────────────────────────────────────────

    private fun buildActivityLog(): JPanel {
        val outer = JPanel(GridBagLayout()).apply { isOpaque = false }

        val alog = CardPanel(12, C_CARD, C_BORDER).apply { layout = GridBagLayout() }
        var ar = 0

        // Header
        val headPanel = JPanel(BorderLayout()).apply { isOpaque = false; border = EmptyBorder(10, 14, 10, 14) }
        val clearBtn  = JButton("Clear").apply {
            isBorderPainted = false; isFocusPainted = false; isOpaque = false
            foreground = C_FGMUT; font = font.deriveFont(10f); cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        }
        headPanel.add(lbl("ACTIVITY LOG", C_FGMUT, 10f, bold = true), BorderLayout.WEST)
        headPanel.add(clearBtn, BorderLayout.EAST)

        // Seed empty message
        appendLogText("No activity yet\n", C_LOG_EMPTY)

        val bodyScroll = JBScrollPane(logPane).apply {
            border = null; isOpaque = false; viewport.isOpaque = false
            preferredSize = Dimension(0, 150); minimumSize = Dimension(0, 150); maximumSize = Dimension(Int.MAX_VALUE, 150)
            verticalScrollBar.unitIncrement = 8
            viewport.background = C_LOG_BG
        }

        clearBtn.addActionListener {
            try { logDoc.remove(0, logDoc.length) } catch (_: Exception) {}
            appendLogText("No activity yet\n", C_LOG_EMPTY)
        }

        alog.add(headPanel, gbc(ar++))
        alog.add(hsep().also { it.maximumSize = Dimension(Int.MAX_VALUE, 1) }, gbc(ar++))
        alog.add(bodyScroll, GridBagConstraints().apply {
            fill = GridBagConstraints.BOTH; weightx = 1.0; weighty = 1.0
            gridwidth = GridBagConstraints.REMAINDER; gridx = 0; gridy = ar
        })

        val wrapGbc = gbc(0, 10, 10).also { it.insets = Insets(10, 10, 12, 10) }
        outer.add(alog, wrapGbc)
        return outer
    }

    private fun appendLogText(text: String, color: Color) {
        val attr = SimpleAttributeSet()
        StyleConstants.setForeground(attr, color)
        StyleConstants.setFontFamily(attr, Font.MONOSPACED)
        StyleConstants.setFontSize(attr, 11)
        try {
            logDoc.insertString(logDoc.length, text, attr)
            logPane.caretPosition = logDoc.length
        } catch (_: Exception) {}
    }

    // ── Wire actions ──────────────────────────────────────────────────────────

    private fun wireActions() {
        startBtn.addActionListener {
            val port = portField.text.trim().toIntOrNull()
            if (port == null || port !in 1..65535) { addLog("Invalid port — enter 1–65535", "ERR"); return@addActionListener }
            val exp = expireValues.getOrNull(expireCombo.selectedIndex)?.takeIf { it.isNotEmpty() }
            svc.startTunnel(port, exp, onLog = { addLog(it) },
                onUrl = { addLog("Tunnel live → $it", "OK"); SwingUtilities.invokeLater { render() } })
            render()
        }
        stopBtn.addActionListener      { svc.stopTunnel();     addLog("Tunnel stopped", "WARN") }
        copyBtn.addActionListener      { svc.publicUrl?.let   { CopyPasteManager.getInstance().setContents(StringSelection(it)); addLog("URL copied", "OK") } }
        openBtn.addActionListener      { svc.publicUrl?.let   { BrowserUtil.browse(it) } }
        liveStartBtn.addActionListener {
            val dir = project?.basePath ?: System.getProperty("user.home")
            svc.startLiveServer(dir, onLog = { addLog(it) },
                onReady = { p ->
                    BrowserUtil.browse("http://localhost:$p")
                    addLog("Opened http://localhost:$p in browser", "OK")
                    SwingUtilities.invokeLater { render() }
                })
            render()
        }
        livePreviewBtn.addActionListener {
            val dir = project?.basePath ?: System.getProperty("user.home")
            svc.startLiveServer(dir, onLog = { addLog(it) },
                onReady = { p -> BrowserUtil.browse("http://localhost:$p"); addLog("Preview → http://localhost:$p", "OK"); SwingUtilities.invokeLater { render() } })
            render()
        }
        liveStopBtn.addActionListener  { svc.stopLiveServer(); addLog("Live Server stopped", "WARN") }
        liveCopyBtn.addActionListener  { svc.livePort?.let    { CopyPasteManager.getInstance().setContents(StringSelection("http://localhost:$it")); addLog("Live URL copied", "OK") } }
        liveOpenBtn.addActionListener  { svc.livePort?.let    { BrowserUtil.browse("http://localhost:$it") } }
        loginBtn.addActionListener {
            loginBtn.isEnabled = false
            loginBtn.text = "Waiting…"
            acctName.text = "Waiting for browser login…"
            acctSub.text  = "Complete login in the browser window"
            addLog("Opening browser — authorize in the browser window", "WARN")
            svc.startDeviceLogin(
                onLog = { msg -> SwingUtilities.invokeLater { addLog(msg) } },
                onDone = { SwingUtilities.invokeLater { loginBtn.text = "Log in"; loginBtn.isEnabled = true; render() } }
            )
        }
        logoutBtn.addActionListener    {
            java.io.File(System.getProperty("user.home"), ".mekong/config.json").delete()
            addLog("Logged out", "WARN"); render()
        }
    }

    // ── Render ────────────────────────────────────────────────────────────────

    private fun render() {
        val running = svc.isRunning
        val url     = svc.publicUrl
        val live    = svc.isLiveRunning

        mainDot.col = when { running && url != null -> C_GREEN; running -> C_ACCENT; live -> C_GREEN; else -> C_DOT_IDLE }
        mainDot.repaint()
        mainLabel.text = when { running && url != null -> "Tunnel active"; running -> "Connecting…"; live -> "Live Server on"; else -> "No active tunnel" }
        mainSub.text   = when { url != null -> url!!; running -> "Waiting for public URL…"; live -> "http://localhost:${svc.livePort}"; else -> "Ready to connect" }

        val email = svc.readSavedEmail()
        if (loginBtn.isEnabled) {  // don't overwrite UI while device login is in flight
            acctName.text       = email ?: "Not logged in"
            acctSub.text        = if (email != null) "Logged in — reserved subdomain active" else "Login for a reserved subdomain"
            loginBtn.isVisible  = email == null
            logoutBtn.isVisible = email != null
        }

        tunnelIdleSection.isVisible   = !running
        tunnelActiveSection.isVisible = running
        urlLabel.text = url ?: "—"

        lsIdleSection.isVisible   = !live
        lsActiveSection.isVisible = live
        liveUrlLabel.text = if (live && svc.livePort != null) "http://localhost:${svc.livePort}" else "—"

        revalidate(); repaint()
    }

    // ── Tabs ──────────────────────────────────────────────────────────────────

    private fun switchTab(name: String) {
        (screens.layout as CardLayout).show(screens, name)
        tabTunnel.active = name == "tunnel"; tabTunnel.repaint()
        tabLive.active   = name == "live";   tabLive.repaint()
    }

    // ── Log ───────────────────────────────────────────────────────────────────

    private fun addLog(msg: String, level: String = "INFO") {
        SwingUtilities.invokeLater {
            val tsColor  = C_LOG_TS
            val msgColor = when (level) {
                "OK"   -> C_SUCC_T
                "WARN" -> C_WARN_T
                "ERR"  -> C_ERR_T
                else   -> C_LOG_FG
            }
            // Remove "no activity" seed text on first real log
            if (logDoc.length > 0 && logDoc.getText(0, logDoc.length).startsWith("No activity")) {
                try { logDoc.remove(0, logDoc.length) } catch (_: Exception) {}
            }
            appendLogText("${df.format(Date())} ", tsColor)
            appendLogText("$msg\n",               msgColor)
        }
    }
}
