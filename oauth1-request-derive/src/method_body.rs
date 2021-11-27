use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned, ToTokens};
use syn::spanned::Spanned;
use syn::{Ident, PathArguments, Type};

use crate::field::Field;
use crate::util::OAuthParameter;

pub struct MethodBody<'a> {
    fields: &'a [Field],
}

impl<'a> MethodBody<'a> {
    pub fn new(fields: &'a [Field]) -> Self {
        MethodBody { fields }
    }
}

impl<'a> ToTokens for MethodBody<'a> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let this = Ident::new("self", Span::mixed_site());
        let ser = Ident::new("serializer", Span::mixed_site());

        let mut next_param = OAuthParameter::default();
        for f in self.fields {
            let ident = &f.ident;

            f.with_renamed(|name| {
                if f.meta.skip {
                    return;
                }

                while next_param < *name.value() {
                    quote!(
                        #ser.#next_param();
                    )
                    .to_tokens(tokens);
                    next_param = next_param.next();
                }

                let ty_is_option = f
                    .meta
                    .option
                    .as_ref()
                    .map(|v| v.value)
                    .unwrap_or_else(|| is_option(&f.ty));

                let value = if ty_is_option {
                    quote_spanned! {f.ty.span()=> {
                        let value = &#this.#ident;
                        ::std::option::Option::as_ref(value).unwrap()
                    }}
                } else {
                    quote! { &#this.#ident }
                };

                let display = if let Some(ref fmt) = f.meta.fmt {
                    quote! {
                        {
                            use std::fmt::{Display, Formatter, Result};

                            // We can't just use `f.ty` instead of `T` because doing so would lead
                            // to E0412/E0261 if `f.ty` contains lifetime/type parameters.
                            struct Adapter<'a, T: 'a + ?Sized, F>(&'a T, F);
                            impl<'a, T: 'a + ?Sized, F> Display for Adapter<'a, T, F>
                            where
                                F: Fn(&T, &mut Formatter<'_>) -> Result,
                            {
                                fn fmt(&self, f: &mut Formatter<'_>) -> Result {
                                    self.1(self.0, f)
                                }
                            }

                            // A helper to make deref coertion from `&#f.ty` to `&T` work properly.
                            struct MakeAdapter<F>(F);
                            impl<F> MakeAdapter<F> {
                                fn make_adapter<T: ?Sized>(self, t: &T) -> Adapter<'_, T, F>
                                where
                                    for<'a> Adapter<'a, T, F>: Display,
                                {
                                    Adapter(t, self.0)
                                }
                            }

                            MakeAdapter
                        }({
                            let fmt: fn(&_, &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result =
                                #fmt;
                            fmt
                        })
                        .make_adapter(#value)
                    }
                } else {
                    value.clone()
                };

                let mut stmt = if f.meta.encoded {
                    quote_spanned! {f.ty.span()=>
                        #ser.serialize_parameter_encoded(#name, #display);
                    }
                } else {
                    quote_spanned! {f.ty.span()=>
                        #ser.serialize_parameter(#name, #display);
                    }
                };
                if let Some(ref skip_if) = f.meta.skip_if {
                    stmt = quote! {
                        if !{
                            let skip_if: fn(&_) -> bool = #skip_if;
                            skip_if
                        }(#value)
                        {
                            #stmt
                        }
                    };
                }
                if ty_is_option {
                    stmt = quote_spanned! {f.ty.span()=>
                        if ::std::option::Option::is_some({
                            let value = &#this.#ident;
                            value
                        }) {
                            #stmt
                        }
                    };
                }
                stmt.to_tokens(tokens);
            });
        }

        while next_param != OAuthParameter::None {
            quote!(
                #ser.#next_param();
            )
            .to_tokens(tokens);
            next_param = next_param.next();
        }
        quote! (
            #ser.end()
        )
        .to_tokens(tokens);
    }
}

fn is_option(mut ty: &Type) -> bool {
    // Types that are interpolated through `macro_rules!` may be enclosed in a `Group`.
    // <https://github.com/rust-lang/rust/pull/72388>
    while let Type::Group(ref g) = *ty {
        ty = &g.elem;
    }

    if let Type::Path(ref ty_path) = *ty {
        let path = &ty_path.path;
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments[0].ident == "Option"
            && match path.segments[0].arguments {
                PathArguments::AngleBracketed(ref args) => args.args.len() == 1,
                PathArguments::None | PathArguments::Parenthesized(_) => false,
            }
    } else {
        false
    }
}
