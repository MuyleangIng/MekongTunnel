-- Partners table
CREATE TABLE IF NOT EXISTS partners (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name         VARCHAR(255) NOT NULL,
  slogan       TEXT         NOT NULL DEFAULT '',
  description  TEXT         NOT NULL DEFAULT '',
  logo_url     TEXT         NOT NULL DEFAULT '',
  website_url  TEXT         NOT NULL DEFAULT '',
  badge        VARCHAR(100) NOT NULL DEFAULT '',
  facebook_url TEXT         NOT NULL DEFAULT '',
  twitter_url  TEXT         NOT NULL DEFAULT '',
  instagram_url TEXT        NOT NULL DEFAULT '',
  linkedin_url TEXT         NOT NULL DEFAULT '',
  github_url   TEXT         NOT NULL DEFAULT '',
  youtube_url  TEXT         NOT NULL DEFAULT '',
  is_active    BOOLEAN      NOT NULL DEFAULT true,
  is_public    BOOLEAN      NOT NULL DEFAULT true,
  sort_order   INTEGER      NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Seed JomNum Tech as the first partner
INSERT INTO partners (name, slogan, description, logo_url, website_url, badge, facebook_url, is_active, is_public, sort_order)
VALUES (
  'JomNum Tech',
  'Moving forward together in the age of technology',
  'A Cambodian technology organization dedicated to growing the local developer community through workshops, mentorship, and collaborative projects.',
  'https://scontent-nrt6-1.xx.fbcdn.net/v/t39.30808-6/360126508_277340118234872_81711176171320814_n.jpg?_nc_cat=111&ccb=1-7&_nc_sid=1d70fc&_nc_ohc=RNtTBEg0yCcQ7kNvwHvpj69&_nc_oc=Adq36lvcGKpo2-5U5sDVB-irSBQBHzE77qZUYp3q2Zl_AYrCEMGrTz5TpLPx1mM_42Q&_nc_zt=23&_nc_ht=scontent-nrt6-1.xx&_nc_gid=ROdN5qt_cTIApkUh0ReDYg&_nc_ss=7a30f&oh=00_Afz4WPNVsFnE9K2gUTwaZtyL0yfMLQMRTN19or4dT6juEg&oe=69C47ADD',
  'https://www.facebook.com/jomnum.tech',
  'Official Partner',
  'https://www.facebook.com/jomnum.tech',
  true, true, 0
) ON CONFLICT DO NOTHING;
