/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Arc2D;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Line2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Iterator;

/**
 * Draws the synthetic mDL portraits of docs/design/20-mdl-issuer.md M-10 (decision D2: no real persons, generated
 * images only): a simple face silhouette in a different palette per portrait, written as a baseline JFIF JPEG by
 * ImageIO so any verifier — Java's ImageIO included — decodes it.
 *
 * <pre>
 *   java docs/design/tools/generate_mdl_portraits.java docker-compose/docker-compose-injistack/config/mdl
 * </pre>
 *
 * Each image is 160x200 at quality 0.55, which lands a few kilobytes, comfortably below the 10 KB the mDL profile
 * allows a portrait element.
 */
class GenerateMdlPortraits {

    private static final int WIDTH = 160;
    private static final int HEIGHT = 200;
    private static final float QUALITY = 0.55f;
    private static final int COUNT = 3;

    private record Palette(Color background, Color skin, Color hair, Color shirt) {}

    private static final Palette[] PALETTES = {
            new Palette(new Color(0xDCE9F5), new Color(0xC68B5A), new Color(0x2B1B12), new Color(0x2F5D8C)),
            new Palette(new Color(0xF1E7D6), new Color(0x8D5524), new Color(0x1A1A1A), new Color(0x5B7F4B)),
            new Palette(new Color(0xEAE0F2), new Color(0xE0AC69), new Color(0x4A2C1A), new Color(0x7B3F6E))
    };

    public static void main(String[] args) throws IOException {
        System.setProperty("java.awt.headless", "true");
        Path directory = Path.of(args.length > 0 ? args[0] : ".");
        for (int i = 0; i < COUNT && i < PALETTES.length; i++) {
            Path out = directory.resolve("portrait-" + (i + 1) + ".jpg");
            BufferedImage image = draw(PALETTES[i]);
            writeJpeg(image, out);
            System.out.println(out + " (" + out.toFile().length() + " bytes, " + WIDTH + "x" + HEIGHT + ")");
        }
    }

    private static BufferedImage draw(Palette palette) {
        BufferedImage image = new BufferedImage(WIDTH, HEIGHT, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        g.setColor(palette.background());
        g.fillRect(0, 0, WIDTH, HEIGHT);

        g.setColor(palette.shirt());
        g.fill(new Ellipse2D.Double(-40, 140, WIDTH + 80, 140));

        g.setColor(palette.skin().darker());
        g.fillRect(WIDTH / 2 - 16, 112, 32, 34);

        g.setColor(palette.skin());
        g.fill(new Ellipse2D.Double(WIDTH / 2 - 42, 26, 84, 96));

        g.setColor(palette.hair());
        g.fill(new Arc2D.Double(WIDTH / 2 - 44, 20, 88, 92, 0, 180, Arc2D.PIE));

        g.setColor(new Color(0x333333));
        g.fillOval(WIDTH / 2 - 28, 74, 14, 9);
        g.fillOval(WIDTH / 2 + 14, 74, 14, 9);

        g.setColor(palette.skin().darker());
        g.draw(new Line2D.Double(WIDTH / 2.0, 82, WIDTH / 2.0, 98));

        g.setColor(new Color(0x9A3B3B));
        g.draw(new Arc2D.Double(WIDTH / 2 - 16, 92, 32, 22, 200, 140, Arc2D.OPEN));

        g.dispose();
        return image;
    }

    private static void writeJpeg(BufferedImage image, Path out) throws IOException {
        Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName("jpeg");
        if (!writers.hasNext()) {
            throw new IllegalStateException("no JPEG writer in this JDK");
        }
        ImageWriter writer = writers.next();
        ImageWriteParam param = writer.getDefaultWriteParam();
        param.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
        param.setCompressionQuality(QUALITY);
        try (ImageOutputStream stream = ImageIO.createImageOutputStream(out.toFile())) {
            writer.setOutput(stream);
            writer.write(null, new IIOImage(image, null, null), param);
        } finally {
            writer.dispose();
        }
    }
}
