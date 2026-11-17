use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct AudioInfo {
    pub duration: f64,
    pub bitrate: i64,
    pub sample_rate: i64,
    pub file_size: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid or corrupted MP3 file: {0}")]
    InvalidMp3(String),
}

const MPEG1_LAYER3_BITRATES: [u32; 16] = [
    0, 32000, 40000, 48000, 56000, 64000, 80000, 96000, 112000, 128000, 160000, 192000, 224000,
    256000, 320000, 0,
];

const MPEG2_LAYER3_BITRATES: [u32; 16] = [
    0, 8000, 16000, 24000, 32000, 40000, 48000, 56000, 64000, 80000, 96000, 112000, 128000, 144000,
    160000, 0,
];

const MPEG1_SAMPLE_RATES: [u32; 4] = [44100, 48000, 32000, 0];
const MPEG2_SAMPLE_RATES: [u32; 4] = [22050, 24000, 16000, 0];
const MPEG25_SAMPLE_RATES: [u32; 4] = [11025, 12000, 8000, 0];

pub fn parse_mp3_file(path: &Path) -> Result<AudioInfo, AudioError> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len();

    if file_size < 4 {
        return Err(AudioError::InvalidMp3("File too small to be MP3".into()));
    }

    // Check for ID3v2 header
    let mut header = [0u8; 10];
    let mut offset = 0u64;
    if file.read_exact(&mut header).is_ok() && &header[0..3] == b"ID3" {
        // ID3v2 tag found. Calculate size from synchsafe integers (7 bits each)
        let tag_size = ((header[6] as u64) << 21)
            | ((header[7] as u64) << 14)
            | ((header[8] as u64) << 7)
            | (header[9] as u64);
        let footer_size = if (header[5] & 0x10) != 0 { 10 } else { 0 };
        offset = 10 + tag_size + footer_size;
    }

    file.seek(SeekFrom::Start(offset))?;

    // Read remaining audio data
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    if buffer.is_empty() {
        return Err(AudioError::InvalidMp3(
            "No audio data found after ID3 header".into(),
        ));
    }

    let mut cursor = 0;
    let mut frame_count = 0u64;
    let mut total_bitrate = 0u64;
    let mut first_sample_rate = 0u32;
    let mut first_bitrate = 0u32;

    while cursor + 4 <= buffer.len() {
        let b0 = buffer[cursor];
        let b1 = buffer[cursor + 1];

        // Frame sync: 11 bits set (0xFF followed by 0b111x_xxxx)
        if b0 == 0xFF && (b1 & 0xE0) == 0xE0 {
            let version_id = (b1 >> 3) & 0x03; // 3 = MPEG-1, 2 = MPEG-2, 0 = MPEG-2.5
            let layer_id = (b1 >> 1) & 0x03; // 1 = Layer III

            if layer_id == 1 && version_id != 1 {
                let b2 = buffer[cursor + 2];
                let bitrate_idx = ((b2 >> 4) & 0x0F) as usize;
                let sample_rate_idx = ((b2 >> 2) & 0x03) as usize;
                let padding = ((b2 >> 1) & 0x01) as u32;

                let bitrate = if version_id == 3 {
                    MPEG1_LAYER3_BITRATES[bitrate_idx]
                } else {
                    MPEG2_LAYER3_BITRATES[bitrate_idx]
                };

                let sample_rate = match version_id {
                    3 => MPEG1_SAMPLE_RATES[sample_rate_idx],
                    2 => MPEG2_SAMPLE_RATES[sample_rate_idx],
                    _ => MPEG25_SAMPLE_RATES[sample_rate_idx],
                };

                if bitrate > 0 && sample_rate > 0 {
                    let _samples_per_frame: u32 = if version_id == 3 { 1152 } else { 576 };
                    let frame_length = if version_id == 3 {
                        ((144 * bitrate) / sample_rate) + padding
                    } else {
                        ((72 * bitrate) / sample_rate) + padding
                    } as usize;

                    if frame_length > 4 && cursor + frame_length <= buffer.len() {
                        if frame_count == 0 {
                            first_sample_rate = sample_rate;
                            first_bitrate = bitrate;
                        }
                        frame_count += 1;
                        total_bitrate += bitrate as u64;
                        cursor += frame_length;
                        continue;
                    }
                }
            }
        }
        cursor += 1;
    }

    if frame_count == 0 {
        return Err(AudioError::InvalidMp3(
            "Parsed MP3 contains no valid audio frames or zero duration".into(),
        ));
    }

    let avg_bitrate = (total_bitrate / frame_count) as i64;
    let sample_rate = first_sample_rate as i64;
    let duration = (frame_count as f64 * 1152.0) / (first_sample_rate as f64);

    Ok(AudioInfo {
        duration,
        bitrate: if avg_bitrate > 0 {
            avg_bitrate
        } else {
            first_bitrate as i64
        },
        sample_rate,
        file_size,
    })
}
