// This file is generated by rust-protobuf 2.28.0. Do not edit
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_imports)]
#![allow(unused_results)]
//! Generated file from `image.proto`

//! Generated by "build.rs" ("build_script_build")

/// Generated files are compatible only with the same version
/// of protobuf runtime.
// const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_2_28_0;

#[derive(PartialEq,Clone,Default)]
#[cfg_attr(feature = "with-serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "with-serde", serde(default))]
pub struct PullImageRequest {
    // message fields
    pub image: ::std::string::String,
    pub container_id: ::std::string::String,
    pub source_creds: ::std::string::String,
    // special fields
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub unknown_fields: ::protobuf::UnknownFields,
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a PullImageRequest {
    fn default() -> &'a PullImageRequest {
        <PullImageRequest as ::protobuf::Message>::default_instance()
    }
}

impl PullImageRequest {
    pub fn new() -> PullImageRequest {
        ::std::default::Default::default()
    }

    // string image = 1;


    pub fn get_image(&self) -> &str {
        &self.image
    }
    pub fn clear_image(&mut self) {
        self.image.clear();
    }

    // Param is passed by value, moved
    pub fn set_image(&mut self, v: ::std::string::String) {
        self.image = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_image(&mut self) -> &mut ::std::string::String {
        &mut self.image
    }

    // Take field
    pub fn take_image(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.image, ::std::string::String::new())
    }

    // string container_id = 2;


    pub fn get_container_id(&self) -> &str {
        &self.container_id
    }
    pub fn clear_container_id(&mut self) {
        self.container_id.clear();
    }

    // Param is passed by value, moved
    pub fn set_container_id(&mut self, v: ::std::string::String) {
        self.container_id = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_container_id(&mut self) -> &mut ::std::string::String {
        &mut self.container_id
    }

    // Take field
    pub fn take_container_id(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.container_id, ::std::string::String::new())
    }

    // string source_creds = 3;


    pub fn get_source_creds(&self) -> &str {
        &self.source_creds
    }
    pub fn clear_source_creds(&mut self) {
        self.source_creds.clear();
    }

    // Param is passed by value, moved
    pub fn set_source_creds(&mut self, v: ::std::string::String) {
        self.source_creds = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_source_creds(&mut self) -> &mut ::std::string::String {
        &mut self.source_creds
    }

    // Take field
    pub fn take_source_creds(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.source_creds, ::std::string::String::new())
    }
}

impl ::protobuf::Message for PullImageRequest {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.image)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.container_id)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.source_creds)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.image.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.image);
        }
        if !self.container_id.is_empty() {
            my_size += ::protobuf::rt::string_size(2, &self.container_id);
        }
        if !self.source_creds.is_empty() {
            my_size += ::protobuf::rt::string_size(3, &self.source_creds);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.image.is_empty() {
            os.write_string(1, &self.image)?;
        }
        if !self.container_id.is_empty() {
            os.write_string(2, &self.container_id)?;
        }
        if !self.source_creds.is_empty() {
            os.write_string(3, &self.source_creds)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> PullImageRequest {
        PullImageRequest::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "image",
                |m: &PullImageRequest| { &m.image },
                |m: &mut PullImageRequest| { &mut m.image },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "container_id",
                |m: &PullImageRequest| { &m.container_id },
                |m: &mut PullImageRequest| { &mut m.container_id },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "source_creds",
                |m: &PullImageRequest| { &m.source_creds },
                |m: &mut PullImageRequest| { &mut m.source_creds },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<PullImageRequest>(
                "PullImageRequest",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static PullImageRequest {
        static instance: ::protobuf::rt::LazyV2<PullImageRequest> = ::protobuf::rt::LazyV2::INIT;
        instance.get(PullImageRequest::new)
    }
}

impl ::protobuf::Clear for PullImageRequest {
    fn clear(&mut self) {
        self.image.clear();
        self.container_id.clear();
        self.source_creds.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for PullImageRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for PullImageRequest {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
#[cfg_attr(feature = "with-serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "with-serde", serde(default))]
pub struct PullImageResponse {
    // message fields
    pub image_ref: ::std::string::String,
    // special fields
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub unknown_fields: ::protobuf::UnknownFields,
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a PullImageResponse {
    fn default() -> &'a PullImageResponse {
        <PullImageResponse as ::protobuf::Message>::default_instance()
    }
}

impl PullImageResponse {
    pub fn new() -> PullImageResponse {
        ::std::default::Default::default()
    }

    // string image_ref = 1;


    pub fn get_image_ref(&self) -> &str {
        &self.image_ref
    }
    pub fn clear_image_ref(&mut self) {
        self.image_ref.clear();
    }

    // Param is passed by value, moved
    pub fn set_image_ref(&mut self, v: ::std::string::String) {
        self.image_ref = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_image_ref(&mut self) -> &mut ::std::string::String {
        &mut self.image_ref
    }

    // Take field
    pub fn take_image_ref(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.image_ref, ::std::string::String::new())
    }
}

impl ::protobuf::Message for PullImageResponse {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.image_ref)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.image_ref.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.image_ref);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.image_ref.is_empty() {
            os.write_string(1, &self.image_ref)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> PullImageResponse {
        PullImageResponse::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "image_ref",
                |m: &PullImageResponse| { &m.image_ref },
                |m: &mut PullImageResponse| { &mut m.image_ref },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<PullImageResponse>(
                "PullImageResponse",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static PullImageResponse {
        static instance: ::protobuf::rt::LazyV2<PullImageResponse> = ::protobuf::rt::LazyV2::INIT;
        instance.get(PullImageResponse::new)
    }
}

impl ::protobuf::Clear for PullImageResponse {
    fn clear(&mut self) {
        self.image_ref.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for PullImageResponse {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for PullImageResponse {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
#[cfg_attr(feature = "with-serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "with-serde", serde(default))]
pub struct MetaContainerRequest {
    // message fields
    pub container_id: ::std::string::String,
    // special fields
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub unknown_fields: ::protobuf::UnknownFields,
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a MetaContainerRequest {
    fn default() -> &'a MetaContainerRequest {
        <MetaContainerRequest as ::protobuf::Message>::default_instance()
    }
}

impl MetaContainerRequest {
    pub fn new() -> MetaContainerRequest {
        ::std::default::Default::default()
    }

    // string container_id = 1;


    pub fn get_container_id(&self) -> &str {
        &self.container_id
    }
    pub fn clear_container_id(&mut self) {
        self.container_id.clear();
    }

    // Param is passed by value, moved
    pub fn set_container_id(&mut self, v: ::std::string::String) {
        self.container_id = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_container_id(&mut self) -> &mut ::std::string::String {
        &mut self.container_id
    }

    // Take field
    pub fn take_container_id(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.container_id, ::std::string::String::new())
    }
}

impl ::protobuf::Message for MetaContainerRequest {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.container_id)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.container_id.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.container_id);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.container_id.is_empty() {
            os.write_string(1, &self.container_id)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> MetaContainerRequest {
        MetaContainerRequest::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "container_id",
                |m: &MetaContainerRequest| { &m.container_id },
                |m: &mut MetaContainerRequest| { &mut m.container_id },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<MetaContainerRequest>(
                "MetaContainerRequest",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static MetaContainerRequest {
        static instance: ::protobuf::rt::LazyV2<MetaContainerRequest> = ::protobuf::rt::LazyV2::INIT;
        instance.get(MetaContainerRequest::new)
    }
}

impl ::protobuf::Clear for MetaContainerRequest {
    fn clear(&mut self) {
        self.container_id.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for MetaContainerRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for MetaContainerRequest {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
#[cfg_attr(feature = "with-serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "with-serde", serde(default))]
pub struct MetaContainerResponse {
    // message fields
    pub digest: ::std::string::String,
    // special fields
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub unknown_fields: ::protobuf::UnknownFields,
    #[cfg_attr(feature = "with-serde", serde(skip))]
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a MetaContainerResponse {
    fn default() -> &'a MetaContainerResponse {
        <MetaContainerResponse as ::protobuf::Message>::default_instance()
    }
}

impl MetaContainerResponse {
    pub fn new() -> MetaContainerResponse {
        ::std::default::Default::default()
    }

    // string digest = 1;


    pub fn get_digest(&self) -> &str {
        &self.digest
    }
    pub fn clear_digest(&mut self) {
        self.digest.clear();
    }

    // Param is passed by value, moved
    pub fn set_digest(&mut self, v: ::std::string::String) {
        self.digest = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_digest(&mut self) -> &mut ::std::string::String {
        &mut self.digest
    }

    // Take field
    pub fn take_digest(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.digest, ::std::string::String::new())
    }
}

impl ::protobuf::Message for MetaContainerResponse {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.digest)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.digest.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.digest);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.digest.is_empty() {
            os.write_string(1, &self.digest)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> MetaContainerResponse {
        MetaContainerResponse::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "digest",
                |m: &MetaContainerResponse| { &m.digest },
                |m: &mut MetaContainerResponse| { &mut m.digest },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<MetaContainerResponse>(
                "MetaContainerResponse",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static MetaContainerResponse {
        static instance: ::protobuf::rt::LazyV2<MetaContainerResponse> = ::protobuf::rt::LazyV2::INIT;
        instance.get(MetaContainerResponse::new)
    }
}

impl ::protobuf::Clear for MetaContainerResponse {
    fn clear(&mut self) {
        self.digest.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for MetaContainerResponse {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for MetaContainerResponse {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x0bimage.proto\x12\x04grpc\"v\n\x10PullImageRequest\x12\x16\n\x05imag\
    e\x18\x01\x20\x01(\tR\x05imageB\0\x12#\n\x0ccontainer_id\x18\x02\x20\x01\
    (\tR\x0bcontainerIdB\0\x12#\n\x0csource_creds\x18\x03\x20\x01(\tR\x0bsou\
    rceCredsB\0:\0\"4\n\x11PullImageResponse\x12\x1d\n\timage_ref\x18\x01\
    \x20\x01(\tR\x08imageRefB\0:\0\"=\n\x14MetaContainerRequest\x12#\n\x0cco\
    ntainer_id\x18\x01\x20\x01(\tR\x0bcontainerIdB\0:\0\"3\n\x15MetaContaine\
    rResponse\x12\x18\n\x06digest\x18\x01\x20\x01(\tR\x06digestB\0:\0B\0b\
    \x06proto3\
";

static file_descriptor_proto_lazy: ::protobuf::rt::LazyV2<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::LazyV2::INIT;

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    file_descriptor_proto_lazy.get(|| {
        parse_descriptor_proto()
    })
}