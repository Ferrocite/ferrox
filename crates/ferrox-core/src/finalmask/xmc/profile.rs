use super::protocol::{read_boolean, read_string, read_uuid, read_varint, Packet};
use std::io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub username: String,
    pub uuid: [u8; 16],
    pub textures_value: String,
    pub textures_signature: String,
}

pub fn profiles_from_config(configured: &[Profile]) -> io::Result<Vec<Profile>> {
    if configured.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty profiles",
        ));
    }

    let mut profiles = Vec::with_capacity(configured.len());
    for profile in configured {
        if profile.username.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid profile",
            ));
        }
        if profile.textures_value.is_empty() || profile.textures_signature.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "incomplete profile textures",
            ));
        }
        profiles.push(profile.clone());
    }
    Ok(profiles)
}

pub fn find_profile<'a>(
    profiles: &'a [Profile],
    username: &str,
    uuid: &[u8; 16],
) -> Option<&'a Profile> {
    profiles
        .iter()
        .find(|profile| profile.username == username && &profile.uuid == uuid)
}

pub fn read_login_success(packet: &Packet) -> io::Result<Profile> {
    let mut data = packet.data.as_slice();
    let uuid = read_uuid(&mut data)?;
    let username = read_string(&mut data)?;
    let property_count = read_varint(&mut data)?;
    let property_name = read_string(&mut data)?;
    let value = read_string(&mut data)?;
    let signed = read_boolean(&mut data)?;
    let signature = read_string(&mut data)?;

    if property_count != 1 || property_name != "textures" || !signed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid login profile properties",
        ));
    }

    Ok(Profile {
        username,
        uuid,
        textures_value: value,
        textures_signature: signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::xmc::protocol::{write_boolean, write_string, write_uuid, write_varint};

    fn profile(username: &str) -> Profile {
        Profile {
            username: username.to_owned(),
            uuid: [0x2a; 16],
            textures_value: "textures-value".to_owned(),
            textures_signature: "textures-signature".to_owned(),
        }
    }

    fn login_success(profile: &Profile, property_name: &str, signed: bool) -> Packet {
        let mut data = Vec::new();
        write_uuid(&mut data, &profile.uuid).expect("uuid");
        write_string(&mut data, &profile.username).expect("username");
        write_varint(&mut data, 1).expect("count");
        write_string(&mut data, property_name).expect("name");
        write_string(&mut data, &profile.textures_value).expect("value");
        write_boolean(&mut data, signed).expect("signed");
        write_string(&mut data, &profile.textures_signature).expect("signature");
        Packet { id: 0x02, data }
    }

    #[test]
    fn empty_profiles_are_rejected() {
        let error = profiles_from_config(&[]).expect_err("empty");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn incomplete_textures_are_rejected() {
        let mut entry = profile("SignedUser");
        entry.textures_signature.clear();
        let error = profiles_from_config(&[entry]).expect_err("incomplete");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn configured_profiles_are_preserved() {
        let profiles = profiles_from_config(&[profile("SignedUser")]).expect("valid");
        assert_eq!(profiles, [profile("SignedUser")]);
    }

    #[test]
    fn a_profile_is_found_by_username_and_uuid() {
        let profiles = [profile("SignedUser")];
        assert!(find_profile(&profiles, "SignedUser", &[0x2a; 16]).is_some());
        assert!(find_profile(&profiles, "SignedUser", &[0x2b; 16]).is_none());
        assert!(find_profile(&profiles, "OtherUser", &[0x2a; 16]).is_none());
    }

    #[test]
    fn a_login_success_body_parses_into_a_profile() {
        let expected = profile("SignedUser");
        let packet = login_success(&expected, "textures", true);
        assert_eq!(read_login_success(&packet).expect("parses"), expected);
    }

    #[test]
    fn login_success_requires_one_signed_textures_property() {
        let expected = profile("SignedUser");
        let wrong_name = login_success(&expected, "cape", true);
        assert_eq!(
            read_login_success(&wrong_name)
                .expect_err("wrong name")
                .kind(),
            io::ErrorKind::InvalidData
        );

        let unsigned = login_success(&expected, "textures", false);
        assert_eq!(
            read_login_success(&unsigned).expect_err("unsigned").kind(),
            io::ErrorKind::InvalidData
        );
    }
}
