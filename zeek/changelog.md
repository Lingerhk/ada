

#### ZEEK (二次开发) V7.1.0
只修改json format输出，以支持zeek-redis plugin
- `scripts/site/local.zeek`
```c++
// disable it
#@load tuning/defaults
```

- `auxil/zeekctl/etc/zeekctl.cfg.in`
```c++
// setting FileExtractDir to empty
FileExtractDir =
```

- `src/threading/formatters/JSON.cc`
```c++
// L61, 在Describe函数下方增加函数DescribeV2:
// Add by adaegis: added hostname into json
bool JSON::DescribeV2(ODesc* desc, int num_fields, const Field* const* fields, Value** vals, const std::string& hostname) const {
    rapidjson::StringBuffer buffer;
    zeek::json::detail::NullDoubleWriter writer(buffer);

    writer.StartObject();

    for ( int i = 0; i < num_fields; i++ ) {
        if ( vals[i]->present || include_unset_fields )
            BuildJSON(writer, vals[i], fields[i]->name);
    }

    // add hostname field
    writer.Key("Hostname");
    const char* hostnameCStr = hostname.c_str();
    size_t length = hostname.length();
    writer.String(hostnameCStr, length);

    writer.EndObject();
    desc->Add(buffer.GetString());

    return true;
}
```

- `src/threading/formatters/JSON.h`
```c++
// L44 增加DescribeV2声明:
        bool DescribeV2(ODesc* desc, int num_fields, const Field* const* fields, Value** vals, const std::string& hostname="") const override;
```

- `src/threading/formatters/Ascii.cc`
```c++
// L70, 在Describe函数下方增加函数DescribeV2:
bool Ascii::DescribeV2(ODesc* desc, int num_fields, const Field* const* fields, Value** vals, const std::string& hostname) const {
    for ( int i = 0; i < num_fields; i++ ) {
        if ( i > 0 )
            desc->AddRaw(separators.separator);

        if ( ! Describe(desc, vals[i], fields[i]->name) )
            return false;
    }

    return true;
}
```

- `src/threading/formatters/Ascii.h`
```c++
// L55, 增加DescribeV2声明:
    virtual bool DescribeV2(ODesc* desc, int num_fields, const Field* const* fields, Value** vals, const std::string& hostname="") const override;
```

- `src/threading/Formatter.h`
```c++
// L58, 增加DescribeV2声明:
virtual bool DescribeV2(ODesc* desc, int num_fields, const Field* const* fields, Value** vals, const std::string& hostname = "") const = 0;
```




